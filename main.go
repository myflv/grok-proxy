// grok-proxy: multi-account Grok reverse proxy.
//
// Loads CPA JSON, sticky account selection, RT auto-refresh (persist to disk),
// 429/402 cooldown + switch, SSO revive on dead RT, permanent *.json.dead after SSO fail.
// Access tokens with JWT claim "bfs" stay in the pool and keep RT refresh, but are
// never selected for upstream requests (re-evaluated after each refresh).
// Clients always see one endpoint and one api_key.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	tokenURL    = "https://auth.x.ai/oauth2/token"
	clientID    = "b1a00492-073a-47ea-816f-4c329264a828"
	oauthScope  = "openid profile email offline_access grok-cli:access api:access"
	upstreamURL = "https://cli-chat-proxy.grok.com/v1"
	cooldownSec = 65
	defaultTTL  = 6 * time.Hour
	maxRetries  = 8 // real upstream tries / account switches; bfs skips do not count
)

// ---------- config ----------

type Config struct {
	Listen            string `json:"listen"`
	APIKey            string `json:"api_key"`
	CPADir            string `json:"cpa_dir"`            // glob, e.g. /data/cpa/*.json
	SSOFile           string `json:"sso_file"`           // accounts.txt or dir
	RefreshInterval   int    `json:"refresh_interval"`   // seconds, default 300
	ReviveEnabled     *bool  `json:"revive_enabled"`     // default true if sso_file set
	ReviveInterval    int    `json:"revive_interval"`    // seconds, default 600
	ReviveConcurrency int    `json:"revive_concurrency"` // default 2
	Proxy             string `json:"proxy"`              // optional outbound proxy: http(s):// or socks5(h):// for OAuth/refresh/upstream
}

// ---------- account ----------

// Account is one CPA credential. Public JSON fields match Grok-Register output.
type Account struct {
	Type         string            `json:"type,omitempty"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	IDToken      string            `json:"id_token,omitempty"`
	TokenType    string            `json:"token_type,omitempty"`
	ExpiresIn    int               `json:"expires_in,omitempty"`
	Expired      string            `json:"expired,omitempty"`
	LastRefresh  string            `json:"last_refresh,omitempty"`
	Sub          string            `json:"sub,omitempty"`
	Email        string            `json:"email"`
	BaseURL      string            `json:"base_url,omitempty"`
	TokenEP      string            `json:"token_endpoint,omitempty"`
	AuthKind     string            `json:"auth_kind,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`

	// runtime only
	mu            sync.Mutex
	refreshMu     sync.Mutex // serialize refresh for this account
	filePath      string
	expiresAt     time.Time
	cooldownUntil time.Time
	dead          bool
	// hasBFS: access_token JWT carries "bfs" claim. Still loaded + RT-refreshed,
	// but skipped when selecting an account for upstream requests.
	hasBFS bool
}

func (a *Account) snapshot() (token, email string, headers map[string]string, dead bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := make(map[string]string, len(a.Headers))
	for k, v := range a.Headers {
		h[k] = v
	}
	return a.AccessToken, a.Email, h, a.dead
}

func (a *Account) isDead() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dead
}

func (a *Account) hasBFSClaim() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hasBFS
}

// usableForRequest: not dead, not bfs-filtered (cooldown checked separately).
func (a *Account) usableForRequest() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.dead && !a.hasBFS
}

func (a *Account) inCooldown() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Before(a.cooldownUntil)
}

// needsRefresh: true when remaining TTL <= lead.
// lead comes from the refresh timer (2×refresh_interval) so a single
// interval scanner is enough — no separate fixed skew.
func (a *Account) needsRefresh(lead time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if lead <= 0 {
		lead = 10 * time.Minute
	}
	return !time.Now().Before(a.expiresAt.Add(-lead))
}

func (a *Account) setCooldown(d time.Duration) {
	a.mu.Lock()
	a.cooldownUntil = time.Now().Add(d)
	a.mu.Unlock()
}

// markDead is called when refresh_token is unusable.
// Flow: soft-disable in pool → try SSO revive → only rename to .json.dead if SSO permanently fails.
// Rate-limited SSO failures stay soft-dead and retry later (file stays *.json).
func (a *Account) markDead(reason string) {
	a.mu.Lock()
	if a.dead {
		a.mu.Unlock()
		return
	}
	a.dead = true // soft: out of selection pool, file not renamed yet
	email := a.Email
	a.mu.Unlock()

	log.Printf("[dead] %s soft-dead (%s)", email, reason)

	if globalReviver != nil {
		// If we know there's no SSO for this email, finalize immediately
		// (avoid queue churn for thousands of no-SSO accounts).
		if globalReviver.sso != nil {
			if _, ok := globalReviver.sso.Get(email); !ok {
				a.finalizeDead(reason + "; no sso")
				return
			}
		}
		globalReviver.Enqueue(email)
		return
	}
	// no SSO reviver configured → permanent dead immediately
	a.finalizeDead(reason)
}

// finalizeDead renames CPA to *.json.dead so next process start skips it forever.
func (a *Account) finalizeDead(reason string) {
	a.mu.Lock()
	a.dead = true
	path := a.filePath
	email := a.Email
	a.mu.Unlock()

	if path == "" {
		log.Printf("[dead] %s permanent (no file): %s", email, reason)
		return
	}
	if strings.HasSuffix(path, ".dead") {
		log.Printf("[dead] %s already .dead (%s)", email, reason)
		return
	}
	newPath := path + ".dead"
	if err := os.Rename(path, newPath); err != nil {
		log.Printf("[dead] %s rename failed: %v", email, err)
		return
	}
	a.mu.Lock()
	a.filePath = newPath
	a.mu.Unlock()
	log.Printf("[dead] %s → %s (%s)", email, filepath.Base(newPath), reason)
}

// set by NewServer when revive enabled
var globalReviver *Reviver

// persist writes current tokens back to the CPA file (atomic rename).
func (a *Account) persist() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.filePath == "" || a.dead {
		return nil
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.filePath)
}

func (a *Account) applyTokens(access, refresh string, expiresIn int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.AccessToken = access
	a.hasBFS = jwtHasClaim(access, "bfs")
	if refresh != "" {
		a.RefreshToken = refresh
	}
	if expiresIn <= 0 {
		expiresIn = int(defaultTTL.Seconds())
	}
	a.ExpiresIn = expiresIn
	now := time.Now()
	a.expiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	a.Expired = a.expiresAt.UTC().Format(time.RFC3339)
	a.LastRefresh = now.UTC().Format(time.RFC3339)
	a.cooldownUntil = time.Time{}
}

// ---------- pool ----------

type Pool struct {
	mu       sync.RWMutex
	accounts []*Account
	// sticky: keep using the same account until it cools down / dies
	cursor  atomic.Uint64 // index of preferred account
	glob    string
	client  *http.Client
	// refreshLead: refresh when remaining TTL <= this. Derived from
	// refresh_interval (2×interval) so one ticker is the only proactive path.
	refreshLead time.Duration
}

// NewPool loads CPA files. refreshLead is how far ahead of exp we refresh;
// typically 2×refresh_interval so one interval scan cannot miss expiry.
func NewPool(glob string, client *http.Client, refreshLead time.Duration) (*Pool, error) {
	if refreshLead <= 0 {
		refreshLead = 10 * time.Minute
	}
	p := &Pool{glob: glob, client: client, refreshLead: refreshLead}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pool) load() error {
	matches, err := filepath.Glob(p.glob)
	if err != nil {
		return fmt.Errorf("glob %s: %w", p.glob, err)
	}

	var list []*Account
	seen := map[string]bool{}
	skippedDead := 0

	for _, path := range matches {
		base := filepath.Base(path)
		low := strings.ToLower(base)
		// only bare *.json — never load *.json.dead (permanent graveyard)
		if strings.HasSuffix(low, ".dead") || strings.HasSuffix(low, ".tmp") {
			skippedDead++
			continue
		}
		if !strings.HasSuffix(low, ".json") {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[load] skip %s: %v", path, err)
			continue
		}
		var acct Account
		if err := json.Unmarshal(data, &acct); err != nil {
			log.Printf("[load] skip %s: %v", path, err)
			continue
		}
		if acct.RefreshToken == "" && acct.AccessToken == "" {
			log.Printf("[load] skip %s: missing tokens", path)
			continue
		}
		key := acct.Email
		if key == "" {
			key = path
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		acct.filePath = path
		acct.dead = false
		acct.hasBFS = jwtHasClaim(acct.AccessToken, "bfs")
		// Prefer JWT exp (source of truth). Fall back to CPA "expired" field.
		// Never default to time.Now() when AT is still valid — that forced a
		// full-pool refresh on every process restart.
		if exp, ok := jwtExp(acct.AccessToken); ok {
			acct.expiresAt = exp
			if acct.Expired == "" {
				acct.Expired = exp.Format(time.RFC3339)
			}
		} else if acct.Expired != "" {
			if t, err := time.Parse(time.RFC3339, acct.Expired); err == nil {
				acct.expiresAt = t
			} else {
				acct.expiresAt = time.Now()
			}
		} else if acct.ExpiresIn > 0 && acct.LastRefresh != "" {
			if lr, err := time.Parse(time.RFC3339, acct.LastRefresh); err == nil {
				acct.expiresAt = lr.Add(time.Duration(acct.ExpiresIn) * time.Second)
			} else {
				acct.expiresAt = time.Now()
			}
		} else {
			acct.expiresAt = time.Now()
		}
		if acct.Headers == nil || len(acct.Headers) == 0 {
			acct.Headers = defaultCPAHeaders()
		}

		list = append(list, &acct)
		if acct.hasBFS {
			log.Printf("[load] %s (expires %s) bfs=yes — refresh only, skip serve",
				acct.Email, acct.expiresAt.Format(time.RFC3339))
		} else {
			log.Printf("[load] %s (expires %s)", acct.Email, acct.expiresAt.Format(time.RFC3339))
		}
	}

	if len(list) == 0 {
		return fmt.Errorf("no valid CPA JSON in %s", p.glob)
	}

	bfsN := 0
	for _, a := range list {
		if a.hasBFS {
			bfsN++
		}
	}
	p.mu.Lock()
	p.accounts = list
	p.mu.Unlock()
	needRef := 0
	for _, a := range list {
		if !a.dead && a.needsRefresh(p.refreshLead) {
			needRef++
		}
	}
	log.Printf("[pool] loaded %d accounts (skipped %d .dead, %d bfs-filtered, %d due-refresh lead=%s)",
		len(list), skippedDead, bfsN, needRef, p.refreshLead)
	return nil
}

func countLive(list []*Account) int {
	n := 0
	for _, a := range list {
		if !a.dead && !a.hasBFS {
			n++
		}
	}
	return n
}

func (p *Pool) findByEmail(email string) *Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, a := range p.accounts {
		if a.Email == email {
			return a
		}
	}
	return nil
}

func (p *Pool) add(a *Account) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.accounts {
		if existing.Email == a.Email {
			return
		}
	}
	p.accounts = append(p.accounts, a)
}

func (p *Pool) liveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, a := range p.accounts {
		// bfs accounts stay in pool for RT refresh but are not "live" for serving
		if a.usableForRequest() {
			n++
		}
	}
	return n
}

func (p *Pool) totalCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.accounts)
}

func (p *Pool) bfsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, a := range p.accounts {
		if a.hasBFSClaim() {
			n++
		}
	}
	return n
}

// selectAccount picks a live account.
// Sticky mode: reuse the current cursor account until it is dead, bfs-filtered, or cooling,
// then advance to the next available one. Not per-request round-robin.
// exclude: skip this email (used when retrying after 429/402/auth fail).
// Accounts whose access_token carries "bfs" are never selected for upstream use
// (they remain in the pool and still get RT refresh).
func (p *Pool) selectAccount(exclude string) *Account {
	p.mu.RLock()
	n := len(p.accounts)
	snapshot := make([]*Account, n)
	copy(snapshot, p.accounts)
	p.mu.RUnlock()
	if n == 0 {
		return nil
	}

	// 1) Prefer sticky cursor (if not excluded / dead / bfs / cooling)
	cur := int(p.cursor.Load() % uint64(n))
	if exclude == "" {
		a := snapshot[cur]
		if a.usableForRequest() && !a.inCooldown() {
			return a
		}
	}

	// 2) Advance from cursor+1 until we find a usable account
	for i := 0; i < n; i++ {
		idx := (cur + 1 + i) % n
		a := snapshot[idx]
		if !a.usableForRequest() || a.Email == exclude || a.inCooldown() {
			continue
		}
		p.cursor.Store(uint64(idx))
		return a
	}

	// 3) Fallback: usable even if cooling (except excluded / bfs / dead)
	for i := 0; i < n; i++ {
		idx := (cur + i) % n
		a := snapshot[idx]
		if !a.usableForRequest() || a.Email == exclude {
			continue
		}
		p.cursor.Store(uint64(idx))
		return a
	}
	return nil
}

// advanceFrom marks that email as exhausted for sticky selection and
// moves cursor to the next account (best-effort).
func (p *Pool) advanceFrom(email string) {
	p.mu.RLock()
	n := len(p.accounts)
	for i, a := range p.accounts {
		if a.Email == email {
			p.cursor.Store(uint64((i + 1) % max(n, 1)))
			break
		}
	}
	p.mu.RUnlock()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *Pool) cooldown(email string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, a := range p.accounts {
		if a.Email == email {
			a.setCooldown(time.Duration(cooldownSec) * time.Second)
			log.Printf("[cooldown] %s %ds", email, cooldownSec)
			return
		}
	}
}

// refreshAll refreshes accounts nearing expiry. Limited concurrency.
func (p *Pool) refreshAll(ctx context.Context) {
	p.mu.RLock()
	accounts := make([]*Account, len(p.accounts))
	copy(accounts, p.accounts)
	p.mu.RUnlock()

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, a := range accounts {
		if a.isDead() || !a.needsRefresh(p.refreshLead) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(acct *Account) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := p.refresh(ctx, acct); err != nil {
				if errors.Is(err, errRefreshSkipped) {
					return // concurrent refresh won; stay quiet
				}
				log.Printf("[refresh] %s failed: %v", acct.Email, err)
				if isFatalAuth(err) {
					acct.markDead(err.Error())
				}
			} else {
				acct.mu.Lock()
				exp := acct.expiresAt
				bfs := acct.hasBFS
				acct.mu.Unlock()
				if bfs {
					log.Printf("[refresh] %s ok (expires %s, bfs)", acct.Email, exp.UTC().Format(time.RFC3339))
				} else {
					log.Printf("[refresh] %s ok (expires %s)", acct.Email, exp.UTC().Format(time.RFC3339))
				}
			}
		}(a)
	}
	wg.Wait()
}

func (p *Pool) refresh(ctx context.Context, a *Account) error {
	// one refresh at a time per account (RT rotation is not concurrent-safe)
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	// Skip if another goroutine already refreshed past the lead window
	// (same threshold as needsRefresh — one rule only).
	a.mu.Lock()
	alreadyFresh := a.AccessToken != "" && time.Now().Before(a.expiresAt.Add(-p.refreshLead))
	a.mu.Unlock()
	if alreadyFresh {
		return errRefreshSkipped
	}

	a.mu.Lock()
	rt := a.RefreshToken
	a.mu.Unlock()
	if rt == "" {
		return fmt.Errorf("no refresh_token")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {clientID},
		"scope":         {oauthScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return &authError{
			status: resp.StatusCode,
			body:   truncate(string(body), 300),
		}
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if tr.AccessToken == "" {
		return fmt.Errorf("empty access_token")
	}

	a.applyTokens(tr.AccessToken, tr.RefreshToken, tr.ExpiresIn)
	if err := a.persist(); err != nil {
		log.Printf("[persist] %s: %v", a.Email, err)
	}
	return nil
}

// ---------- auth error ----------

// errRefreshSkipped: another goroutine already refreshed; not a failure.
// refreshAll must not log this as "[refresh] ok" (no token exchange happened).
var errRefreshSkipped = fmt.Errorf("refresh skipped: already fresh")

type authError struct {
	status int
	body   string
}

func (e *authError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

func isFatalAuth(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "invalid_grant") ||
		strings.Contains(s, "revoked") ||
		strings.Contains(s, "Token has been revoked") ||
		strings.Contains(s, "invalid_token")
}

// ---------- reverse proxy transport ----------

type accountKey struct{}

type retryTransport struct {
	pool      *Pool
	transport http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// strip internal headers before upstream
	req.Header.Del("X-Proxy-Account")
	req.Header.Del("X-Proxy-Error")

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	acct, _ := req.Context().Value(accountKey{}).(*Account)

	// maxRetries = real upstream tries / account switches (429/402/401).
	// bfs/dead reselects do not consume a slot — selectAccount never returns them.
	for attempt := 0; attempt < maxRetries; attempt++ {
		var token, email string
		var headers map[string]string

		// Pick a servable account. Inner loop is free w.r.t. maxRetries — only for
		// rare races (bfs flips mid-flight). Hard-capped so it cannot spin.
		gotToken := false
		for reselect := 0; reselect < 16; reselect++ {
			if acct == nil || !acct.usableForRequest() {
				exclude := ""
				if acct != nil {
					exclude = acct.Email
				}
				acct = t.pool.selectAccount(exclude)
			}
			if acct == nil {
				return jsonResponse(http.StatusServiceUnavailable, map[string]any{
					"error": "no account available",
				}), nil
			}

			var dead bool
			token, email, headers, dead = acct.snapshot()
			if dead || acct.hasBFSClaim() {
				// race / post-refresh flip — drop without burning attempt
				acct = nil
				continue
			}
			// access empty but may still have RT — try refresh once
			if token == "" {
				ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
				refErr := t.pool.refresh(ctx, acct)
				cancel()
				if refErr != nil {
					if isFatalAuth(refErr) {
						acct.markDead(refErr.Error())
					}
					t.pool.advanceFrom(email)
					acct = t.pool.selectAccount(email)
					// burn this attempt: we engaged the account and moved on
					break
				}
				token, email, headers, dead = acct.snapshot()
				if dead || acct.hasBFSClaim() {
					// refreshed into bfs — skip free, do not burn attempt
					t.pool.advanceFrom(email)
					acct = nil
					continue
				}
				if token == "" {
					t.pool.advanceFrom(email)
					acct = t.pool.selectAccount(email)
					break // empty after refresh → burn attempt, switch
				}
			}
			gotToken = true
			break
		}
		if !gotToken {
			// failed empty-token refresh path, or reselect cap — next attempt
			continue
		}

		// rebuild request for this attempt
		r2 := req.Clone(req.Context())
		if body != nil {
			r2.Body = io.NopCloser(bytes.NewReader(body))
			r2.ContentLength = int64(len(body))
		}
		// CPA headers first, then force Authorization (never let CPA/client override)
		for k, v := range headers {
			if strings.EqualFold(k, "Authorization") {
				continue
			}
			r2.Header.Set(k, v)
		}
		r2.Header.Set("Authorization", "Bearer "+token)
		r2.Header.Del("X-Proxy-Account")
		r2.Header.Del("X-Proxy-Error")

		resp, err := t.transport.RoundTrip(r2)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			// rate limit → cooldown + try next account
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			t.pool.cooldown(email)
			t.pool.advanceFrom(email)
			log.Printf("[retry] %s 429 → next", email)
			acct = t.pool.selectAccount(email)
			continue

		case http.StatusPaymentRequired: // 402 spending-limit / no credits
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// free-tier quota: long cooldown, don't permanently kill
			acct.setCooldown(time.Hour)
			t.pool.advanceFrom(email)
			log.Printf("[retry] %s 402 quota → cooldown 1h, next", email)
			acct = t.pool.selectAccount(email)
			continue

		case http.StatusUnauthorized, http.StatusForbidden:
			// auth failure → refresh once, else mark dead / switch
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
			refErr := t.pool.refresh(ctx, acct)
			cancel()
			if refErr == nil {
				log.Printf("[retry] %s %d → refreshed, retry", email, resp.StatusCode)
				// same account, new token
				continue
			}
			log.Printf("[retry] %s %d refresh failed: %v", email, resp.StatusCode, refErr)
			if isFatalAuth(refErr) || isFatalAuth(fmt.Errorf("%s", string(respBody))) {
				acct.markDead(refErr.Error())
			} else {
				acct.setCooldown(time.Duration(cooldownSec) * time.Second)
			}
			t.pool.advanceFrom(email)
			acct = t.pool.selectAccount(email)
			continue
		}

		// success or other status — pass through
		return resp, nil
	}

	return jsonResponse(http.StatusTooManyRequests, map[string]any{
		"error": "all accounts rate-limited or unavailable",
	}), nil
}

func jsonResponse(code int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
	}
}

// ---------- server ----------

type Server struct {
	cfg     Config
	pool    *Pool
	proxy   *httputil.ReverseProxy
	client  *http.Client
	reviver *Reviver
	sso     *SSOStore
}

func NewServer(cfg Config) (*Server, error) {
	transport, err := buildTransport(cfg.Proxy)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: transport}
	intervalSec := cfg.RefreshInterval
	if intervalSec <= 0 {
		intervalSec = 300
	}
	// Single proactive path: ticker every interval. Refresh when remaining TTL
	// <= 2×interval so one missed beat still leaves a full interval of margin.
	refreshLead := time.Duration(intervalSec*2) * time.Second
	pool, err := NewPool(cfg.CPADir, client, refreshLead)
	if err != nil {
		return nil, err
	}

	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, pool: pool, client: client}

	// SSO revive (optional)
	reviveOn := cfg.SSOFile != ""
	if cfg.ReviveEnabled != nil {
		reviveOn = *cfg.ReviveEnabled && cfg.SSOFile != ""
	}
	if reviveOn {
		sso, err := LoadSSO(cfg.SSOFile)
		if err != nil {
			return nil, fmt.Errorf("sso: %w", err)
		}
		oa, err := NewSSOOAuth(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("sso oauth: %w", err)
		}
		workers := cfg.ReviveConcurrency
		if workers <= 0 {
			workers = 2
		}
		s.sso = sso
		s.reviver = NewReviver(pool, sso, oa, cpaDirFromGlob(cfg.CPADir), workers)
		globalReviver = s.reviver
		log.Printf("[revive] enabled sso=%d workers=%d", sso.Len(), workers)
	}

	s.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
		Transport:     &retryTransport{pool: pool, transport: transport},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[proxy] %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		},
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
		h := map[string]any{
			"ok":    true,
			"live":  s.pool.liveCount(),
			"total": s.pool.totalCount(),
			"bfs":   s.pool.bfsCount(),
		}
		if s.sso != nil {
			h["sso"] = s.sso.Len()
		}
		if s.reviver != nil {
			h["revive_queue"] = s.reviver.queueSize()
		}
		writeJSON(w, 200, h)
		return
	}

	if s.cfg.APIKey != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("x-api-key")
		}
		if got != s.cfg.APIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
	}

	if s.pool.liveCount() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no live accounts"})
		return
	}

	// sticky account: reuse until 429/402/dead
	acct := s.pool.selectAccount("")
	if acct != nil {
		r = r.WithContext(context.WithValue(r.Context(), accountKey{}, acct))
	}
	s.proxy.ServeHTTP(w, r)
}

// refreshLoop is the only proactive refresh scheduler.
// Every refresh_interval seconds it scans the whole pool and refreshes
// accounts whose remaining TTL <= 2×interval (see Pool.refreshLead).
// On-demand refresh still exists for 401 / empty AT during requests.
func (s *Server) refreshLoop(ctx context.Context) {
	interval := s.cfg.RefreshInterval
	if interval <= 0 {
		interval = 300
	}
	log.Printf("[refresh] interval=%ds lead=%s (refresh when TTL≤lead)",
		interval, s.pool.refreshLead)
	// one pass at boot, then only the ticker
	s.pool.refreshAll(ctx)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pool.refreshAll(ctx)
		}
	}
}

func (s *Server) reviveLoop(ctx context.Context) {
	if s.reviver == nil {
		return
	}
	sec := s.cfg.ReviveInterval
	if sec <= 0 {
		sec = 600
	}
	s.reviver.Loop(ctx, time.Duration(sec)*time.Second)
}

// ---------- main ----------

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":5001"
	}
	if cfg.CPADir == "" {
		log.Fatal("cpa_dir is required")
	}

	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go srv.refreshLoop(ctx)
	go srv.reviveLoop(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("grok-proxy listening on %s (live=%d total=%d)",
		cfg.Listen, srv.pool.liveCount(), srv.pool.totalCount())
	if cfg.APIKey != "" {
		log.Printf("auth: enabled")
	} else {
		log.Printf("auth: disabled")
	}
	if srv.reviver != nil {
		ri := cfg.ReviveInterval
		if ri <= 0 {
			ri = 600
		}
		rc := cfg.ReviveConcurrency
		if rc <= 0 {
			rc = 2
		}
		log.Printf("revive: sso-backed (interval=%ds concurrency=%d sso=%d)",
			ri, rc, srv.sso.Len())
	}

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Printf("shutdown")
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
