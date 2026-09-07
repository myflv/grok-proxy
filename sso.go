package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SSOEntry is one line from Grok-Register SSO/accounts.txt:
//
//	email:password:sso_jwt
type SSOEntry struct {
	Email    string
	Password string
	SSO      string
}

// SSOStore maps email → SSO cookie.
type SSOStore struct {
	mu   sync.RWMutex
	by   map[string]SSOEntry
	path string
}

func LoadSSO(path string) (*SSOStore, error) {
	s := &SSOStore{by: map[string]SSOEntry{}, path: path}
	if path == "" {
		return s, nil
	}

	var files []string
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		// directory: accounts.txt or any *.txt
		if matches, _ := filepath.Glob(filepath.Join(path, "accounts.txt")); len(matches) > 0 {
			files = append(files, matches...)
		}
		if matches, _ := filepath.Glob(filepath.Join(path, "*.txt")); len(matches) > 0 {
			files = append(files, matches...)
		}
		// one level of subdirs (outputs/*/SSO/accounts.txt style if mounted that way)
		if matches, _ := filepath.Glob(filepath.Join(path, "*", "accounts.txt")); len(matches) > 0 {
			files = append(files, matches...)
		}
		if matches, _ := filepath.Glob(filepath.Join(path, "*", "SSO", "accounts.txt")); len(matches) > 0 {
			files = append(files, matches...)
		}
	} else if matches, err := filepath.Glob(path); err == nil && len(matches) > 0 {
		files = matches
	} else {
		files = []string{path}
	}

	// de-dupe file list
	seenF := map[string]bool{}
	for _, f := range files {
		if seenF[f] {
			continue
		}
		seenF[f] = true
		c, err := loadSSOFile(f)
		if err != nil {
			log.Printf("[sso] skip %s: %v", f, err)
			continue
		}
		for email, e := range c {
			s.by[email] = e // last wins
		}
	}
	log.Printf("[sso] loaded %d unique emails from %d file(s)", len(s.by), len(seenF))
	return s, nil
}

func loadSSOFile(path string) (map[string]SSOEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]SSOEntry{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// email:password:sso
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		email := line[:i]
		rest := line[i+1:]
		j := strings.IndexByte(rest, ':')
		if j < 0 {
			continue
		}
		pass := rest[:j]
		sso := rest[j+1:]
		if email == "" || sso == "" {
			continue
		}
		out[email] = SSOEntry{Email: email, Password: pass, SSO: sso}
	}
	return out, sc.Err()
}

func (s *SSOStore) Get(email string) (SSOEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.by[email]
	return e, ok
}

func (s *SSOStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.by)
}

func (s *SSOStore) MarkBad(email string) {
	s.mu.Lock()
	delete(s.by, email)
	s.mu.Unlock()
	log.Printf("[sso] drop bad session %s", email)
}

func defaultCPAHeaders() map[string]string {
	return map[string]string{
		"User-Agent":               "grok-shell/1.0.13 (linux; x86_64)",
		"X-XAI-Token-Auth":         "xai-grok-cli",
		"x-authenticateresponse":   "authenticate-response",
		"x-compaction-at":          "400000",
		"x-grok-client-identifier": "grok-shell",
		"x-grok-client-version":    "1.0.13",
		"x-xai-token-auth":         "xai-grok-cli",
	}
}

func cpaFilename(email string) string {
	sum := sha1.Sum([]byte(email))
	return "xai-" + hex.EncodeToString(sum[:])[:16] + ".json"
}

func cpaDirFromGlob(glob string) string {
	dir := filepath.Dir(glob)
	if dir == "" || dir == "." {
		return "cpa"
	}
	return dir
}

func ensureCPAPath(dir, email, existing string) string {
	if existing != "" {
		p := existing
		if strings.HasSuffix(p, ".dead") {
			p = strings.TrimSuffix(p, ".dead")
		}
		if strings.HasSuffix(p, ".json") {
			return p
		}
	}
	return filepath.Join(dir, cpaFilename(email))
}

func writeAccountFile(path string, a *Account) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	a.mu.Lock()
	m := map[string]any{
		"type":           "xai",
		"access_token":   a.AccessToken,
		"refresh_token":  a.RefreshToken,
		"id_token":       a.IDToken,
		"token_type":     a.TokenType,
		"expires_in":     a.ExpiresIn,
		"expired":        a.Expired,
		"last_refresh":   a.LastRefresh,
		"sub":            a.Sub,
		"email":          a.Email,
		"base_url":       a.BaseURL,
		"token_endpoint": a.TokenEP,
		"auth_kind":      a.AuthKind,
		"headers":        a.Headers,
	}
	a.mu.Unlock()
	if m["base_url"] == "" {
		m["base_url"] = upstreamURL
	}
	if m["token_endpoint"] == "" {
		m["token_endpoint"] = tokenURL
	}
	if m["auth_kind"] == "" {
		m["auth_kind"] = "oauth"
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = os.Remove(path + ".dead")
	return os.Rename(tmp, path)
}
