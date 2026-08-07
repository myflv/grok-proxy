package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Device OAuth via SSO cookie (no browser). Ported from Grok-Register flow.

const (
	discoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	verifyURL    = "https://auth.x.ai/oauth2/device/verify"
	approveURL   = "https://auth.x.ai/oauth2/device/approve"
	oauthUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

type deviceFlow struct {
	DeviceCode      string
	UserCode        string
	VerificationURL string
	ExpiresIn       int
	Interval        float64
	TokenEndpoint   string
}

type oauthTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Subject      string
	Email        string
	TokenEP      string
}

// SSOOAuth does device-code OAuth authorized by an existing sso cookie.
type SSOOAuth struct {
	client *http.Client
	ua     string

	mu        sync.Mutex
	cooldown  time.Time // global rate-limit gate
	tripCount int
}

func NewSSOOAuth(proxy string) (*SSOOAuth, error) {
	tr, err := buildTransport(proxy)
	if err != nil {
		return nil, err
	}
	return &SSOOAuth{
		client: &http.Client{
			Timeout:   45 * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ua: oauthUA,
	}, nil
}

func (o *SSOOAuth) waitGate(ctx context.Context) error {
	for {
		o.mu.Lock()
		until := o.cooldown
		o.mu.Unlock()
		if until.IsZero() || time.Now().After(until) {
			return nil
		}
		wait := time.Until(until)
		if wait < 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (o *SSOOAuth) trip(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tripCount++
	// grow: 2min, 3min, 4.5min... cap 15min (device OAuth is easily throttled)
	if d <= 0 {
		d = 2 * time.Minute
		for i := 1; i < o.tripCount && d < 15*time.Minute; i++ {
			d = time.Duration(float64(d) * 1.5)
		}
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
	}
	o.cooldown = time.Now().Add(d)
	log.Printf("[oauth] rate-limit gate %s (trip=%d)", d.Round(time.Second), o.tripCount)
}

func (o *SSOOAuth) clearTrip() {
	o.mu.Lock()
	o.tripCount = 0
	o.cooldown = time.Time{}
	o.mu.Unlock()
}

// Exchange runs full device flow with SSO cookie.
func (o *SSOOAuth) Exchange(ctx context.Context, sso string) (oauthTokens, error) {
	if err := o.waitGate(ctx); err != nil {
		return oauthTokens{}, err
	}
	flow, err := o.startDevice(ctx)
	if err != nil {
		if isOAuthRateLimit(err) {
			o.trip(0)
		}
		return oauthTokens{}, err
	}
	if err := o.confirm(ctx, sso, flow); err != nil {
		if isOAuthRateLimit(err) {
			o.trip(0)
		}
		return oauthTokens{}, err
	}
	tok, err := o.poll(ctx, flow)
	if err != nil {
		return oauthTokens{}, err
	}
	o.clearTrip()
	return tok, nil
}

func isOAuthRateLimit(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "429") ||
		strings.Contains(s, "rate_limited") ||
		strings.Contains(s, "slow_down") ||
		strings.Contains(s, "too many")
}

func (o *SSOOAuth) startDevice(ctx context.Context) (deviceFlow, error) {
	devEP, tokEP, err := o.discover(ctx)
	if err != nil {
		return deviceFlow{}, err
	}
	form := url.Values{
		"client_id": {clientID},
		"scope":     {oauthScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, devEP, strings.NewReader(form.Encode()))
	if err != nil {
		return deviceFlow{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", o.ua)
	resp, err := o.client.Do(req)
	if err != nil {
		return deviceFlow{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	// Real body when hammered:
	// HTTP 429 {"error":"slow_down","error_description":"Too many device code requests..."}
	if resp.StatusCode == 429 || strings.Contains(strings.ToLower(string(body)), "slow_down") {
		errCode := "slow_down"
		var doc map[string]any
		if json.Unmarshal(body, &doc) == nil {
			if e, ok := doc["error"].(string); ok && e != "" {
				errCode = e
			}
		}
		return deviceFlow{}, fmt.Errorf("%s: device authorization HTTP %d", errCode, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		return deviceFlow{}, fmt.Errorf("device authorization status=%d body=%s", resp.StatusCode, truncate(string(body), 120))
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return deviceFlow{}, err
	}
	dc, _ := doc["device_code"].(string)
	uc, _ := doc["user_code"].(string)
	baseURL, _ := doc["verification_uri"].(string)
	if baseURL == "" {
		baseURL, _ = doc["verification_url"].(string)
	}
	exp, _ := doc["expires_in"].(float64)
	interval, _ := doc["interval"].(float64)
	if interval <= 0 {
		interval = 5
	}
	vurl, _ := doc["verification_uri_complete"].(string)
	if vurl == "" && baseURL != "" {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		vurl = baseURL + sep + "user_code=" + url.QueryEscape(uc)
	}
	if dc == "" || uc == "" {
		return deviceFlow{}, fmt.Errorf("device flow missing codes")
	}
	return deviceFlow{
		DeviceCode:      dc,
		UserCode:        uc,
		VerificationURL: vurl,
		ExpiresIn:       int(exp),
		Interval:        interval,
		TokenEndpoint:   tokEP,
	}, nil
}

func (o *SSOOAuth) discover(ctx context.Context) (deviceEP, tokenEP string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", o.ua)
	resp, err := o.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("discovery status=%d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", err
	}
	deviceEP, _ = doc["device_authorization_endpoint"].(string)
	tokenEP, _ = doc["token_endpoint"].(string)
	if deviceEP == "" || tokenEP == "" {
		return "", "", fmt.Errorf("discovery missing endpoints")
	}
	return deviceEP, tokenEP, nil
}

func (o *SSOOAuth) confirm(ctx context.Context, sso string, flow deviceFlow) error {
	cookie := "sso=" + sso
	// verify
	form := url.Values{"user_code": {flow.UserCode}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	o.setFormHeaders(req, flow.VerificationURL, cookie)
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err := locationError(loc); err != nil {
		return err
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("sso challenge")
	}
	if strings.Contains(loc, "/oauth2/device/done") {
		return nil
	}

	// approve
	consentRef := loc
	if consentRef == "" {
		consentRef = "https://accounts.x.ai/oauth2/device/consent?user_code=" + url.QueryEscape(flow.UserCode)
	} else if strings.HasPrefix(consentRef, "/") {
		consentRef = "https://accounts.x.ai" + consentRef
	}
	aform := url.Values{
		"user_code":      {flow.UserCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {""},
	}
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, approveURL, strings.NewReader(aform.Encode()))
	if err != nil {
		return err
	}
	o.setFormHeaders(req2, consentRef, cookie)
	resp2, err := o.client.Do(req2)
	if err != nil {
		return err
	}
	aloc := resp2.Header.Get("Location")
	body, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	_ = resp2.Body.Close()
	if err := locationError(aloc); err != nil {
		return err
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "device authorized") || strings.Contains(string(body), "设备已授权") {
		return nil
	}
	if resp2.StatusCode/100 == 2 || strings.Contains(aloc, "device/done") || (aloc != "" && locationError(aloc) == nil) {
		return nil
	}
	if resp2.StatusCode == 403 {
		return fmt.Errorf("sso challenge")
	}
	return fmt.Errorf("approve failed status=%d", resp2.StatusCode)
}

func (o *SSOOAuth) setFormHeaders(req *http.Request, referer, cookie string) {
	req.Header.Set("User-Agent", o.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://accounts.x.ai")
	req.Header.Set("Referer", referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
}

func (o *SSOOAuth) poll(ctx context.Context, flow deviceFlow) (oauthTokens, error) {
	deadline := time.Now().Add(time.Duration(flow.ExpiresIn) * time.Second)
	if flow.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(flow.Interval * float64(time.Second))
	if interval < time.Second {
		interval = 5 * time.Second
	}
	ep := flow.TokenEndpoint
	if ep == "" {
		ep = tokenURL
	}
	for time.Now().Before(deadline) {
		form := url.Values{
			"client_id":   {clientID},
			"device_code": {flow.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
		if err != nil {
			return oauthTokens{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", o.ua)
		resp, err := o.client.Do(req)
		if err != nil {
			return oauthTokens{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if resp.StatusCode/100 == 2 {
			return tokensFrom(doc, ep)
		}
		errCode, _ := doc["error"].(string)
		switch errCode {
		case "authorization_pending":
			// keep waiting
		case "slow_down":
			interval += time.Second
		case "access_denied":
			return oauthTokens{}, fmt.Errorf("oauth_denied")
		case "expired_token":
			return oauthTokens{}, fmt.Errorf("oauth_expired")
		default:
			if errCode != "" {
				return oauthTokens{}, fmt.Errorf("oauth_rejected: %s", errCode)
			}
			return oauthTokens{}, fmt.Errorf("oauth_rejected status=%d", resp.StatusCode)
		}
		select {
		case <-ctx.Done():
			return oauthTokens{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return oauthTokens{}, fmt.Errorf("oauth_expired")
}

func tokensFrom(doc map[string]any, ep string) (oauthTokens, error) {
	at, _ := doc["access_token"].(string)
	rt, _ := doc["refresh_token"].(string)
	if at == "" || rt == "" {
		return oauthTokens{}, fmt.Errorf("oauth missing tokens")
	}
	id, _ := doc["id_token"].(string)
	tt, _ := doc["token_type"].(string)
	expF, _ := doc["expires_in"].(float64)
	exp := int(expF)
	if exp <= 0 {
		exp = 21600
	}
	sub := jwtClaim(id, "sub")
	if sub == "" {
		sub = jwtClaim(at, "sub")
	}
	email := jwtClaim(id, "email")
	return oauthTokens{
		AccessToken:  at,
		RefreshToken: rt,
		IDToken:      id,
		TokenType:    tt,
		ExpiresIn:    exp,
		Subject:      sub,
		Email:        email,
		TokenEP:      ep,
	}, nil
}

// jwtPayload decodes the middle segment of a JWT without verifying the signature.
func jwtPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func jwtClaim(token, key string) string {
	m := jwtPayload(token)
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// jwtHasClaim reports whether key exists in the JWT payload (any JSON type).
func jwtHasClaim(token, key string) bool {
	m := jwtPayload(token)
	if m == nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// jwtExp returns the JWT "exp" claim as UTC time. ok=false if missing/invalid.
func jwtExp(token string) (time.Time, bool) {
	return jwtExpFromPayload(jwtPayload(token))
}

func jwtExpFromPayload(m map[string]any) (time.Time, bool) {
	if m == nil {
		return time.Time{}, false
	}
	switch v := m["exp"].(type) {
	case float64:
		if v <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(v), 0).UTC(), true
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return time.Time{}, false
		}
		return time.Unix(n, 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

// jwtInspectAccess decodes an access_token once for load/refresh bookkeeping.
func jwtInspectAccess(token string) (hasBFS bool, exp time.Time, expOK bool) {
	m := jwtPayload(token)
	if m == nil {
		return false, time.Time{}, false
	}
	_, hasBFS = m["bfs"]
	exp, expOK = jwtExpFromPayload(m)
	return hasBFS, exp, expOK
}

func locationError(loc string) error {
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	e := u.Query().Get("error")
	if e == "" {
		return nil
	}
	if e == "rate_limited" {
		return fmt.Errorf("rate_limited")
	}
	return fmt.Errorf("%s", e)
}
