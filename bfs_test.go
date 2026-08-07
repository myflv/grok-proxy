package main

import (
	"encoding/base64"
	"errors"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeJWT(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "at+jwt"})
	p, _ := json.Marshal(claims)
	enc := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(h) + "." + enc(p) + ".sig"
}

func TestJwtHasClaimBFS(t *testing.T) {
	with := makeJWT(map[string]any{"sub": "u1", "bfs": 2})
	without := makeJWT(map[string]any{"sub": "u2"})
	if !jwtHasClaim(with, "bfs") {
		t.Fatal("expected bfs present")
	}
	if jwtHasClaim(without, "bfs") {
		t.Fatal("expected bfs absent")
	}
	// non-string claim still detected
	if !jwtHasClaim(makeJWT(map[string]any{"bfs": true}), "bfs") {
		t.Fatal("bool bfs should count")
	}
	if jwtHasClaim("not-a-jwt", "bfs") {
		t.Fatal("garbage should be false")
	}
}

func TestSelectAccountSkipsBFS(t *testing.T) {
	bfsAcct := &Account{Email: "bfs@x.ai", AccessToken: makeJWT(map[string]any{"bfs": 2}), hasBFS: true}
	okAcct := &Account{Email: "ok@x.ai", AccessToken: makeJWT(map[string]any{"sub": "x"}), hasBFS: false}
	p := &Pool{accounts: []*Account{bfsAcct, okAcct}}
	got := p.selectAccount("")
	if got == nil || got.Email != "ok@x.ai" {
		t.Fatalf("want ok@x.ai, got %#v", got)
	}
	// only bfs left
	p2 := &Pool{accounts: []*Account{bfsAcct}}
	if p2.selectAccount("") != nil {
		t.Fatal("expected nil when only bfs accounts")
	}
	if p2.liveCount() != 0 {
		t.Fatalf("liveCount want 0, got %d", p2.liveCount())
	}
	if p2.bfsCount() != 1 {
		t.Fatalf("bfsCount want 1, got %d", p2.bfsCount())
	}
	if p.liveCount() != 1 {
		t.Fatalf("liveCount want 1, got %d", p.liveCount())
	}
}

func TestApplyTokensUpdatesBFS(t *testing.T) {
	a := &Account{}
	a.applyTokens(makeJWT(map[string]any{"bfs": 2}), "rt", 3600)
	if !a.hasBFSClaim() {
		t.Fatal("expected hasBFS after apply")
	}
	a.applyTokens(makeJWT(map[string]any{"sub": "u"}), "rt", 3600)
	if a.hasBFSClaim() {
		t.Fatal("expected hasBFS cleared after re-apply without claim")
	}
}

func TestSelectAccountNeverReturnsBFS(t *testing.T) {
	// Many bfs accounts must not be handed out even under repeated select.
	list := make([]*Account, 0, 20)
	for i := 0; i < 10; i++ {
		list = append(list, &Account{
			Email:  "bfs" + string(rune('a'+i)) + "@x.ai",
			hasBFS: true,
		})
	}
	list = append(list, &Account{Email: "ok@x.ai", hasBFS: false})
	pool := &Pool{accounts: list}
	for i := 0; i < 20; i++ {
		a := pool.selectAccount("")
		if a == nil {
			t.Fatal("expected ok account")
		}
		if a.hasBFS || a.Email != "ok@x.ai" {
			t.Fatalf("select returned bfs/wrong: %#v", a)
		}
		// sticky will keep returning ok — that's fine
	}
	// only bfs → nil, never a bfs account
	only := &Pool{accounts: list[:10]}
	for i := 0; i < 5; i++ {
		if a := only.selectAccount(""); a != nil {
			t.Fatalf("expected nil, got %s bfs=%v", a.Email, a.hasBFS)
		}
	}
}

func TestJwtExp(t *testing.T) {
	exp := time.Now().UTC().Add(3 * time.Hour).Unix()
	tok := makeJWT(map[string]any{"sub": "u", "exp": float64(exp)})
	got, ok := jwtExp(tok)
	if !ok {
		t.Fatal("expected ok")
	}
	if got.Unix() != exp {
		t.Fatalf("exp=%d got=%d", exp, got.Unix())
	}
	if _, ok := jwtExp(makeJWT(map[string]any{"sub": "u"})); ok {
		t.Fatal("missing exp should be false")
	}
	if _, ok := jwtExp("bad"); ok {
		t.Fatal("garbage should be false")
	}
}

func TestLoadUsesJWTExpNotNow(t *testing.T) {
	dir := t.TempDir()
	exp := time.Now().UTC().Add(4 * time.Hour).Truncate(time.Second)
	tok := makeJWT(map[string]any{
		"sub": "u1",
		"exp": float64(exp.Unix()),
	})
	// intentionally omit "expired" field — old code would set expiresAt=now and refresh
	body := map[string]any{
		"access_token":  tok,
		"refresh_token": "rt-test",
		"email":         "jwt-exp@x.ai",
	}
	raw, _ := json.MarshalIndent(body, "", "  ")
	path := filepath.Join(dir, "a.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(filepath.Join(dir, "*.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.accounts) != 1 {
		t.Fatalf("want 1 account, got %d", len(pool.accounts))
	}
	a := pool.accounts[0]
	if a.needsRefresh() {
		t.Fatalf("fresh JWT should not need refresh; expiresAt=%s now=%s",
			a.expiresAt, time.Now())
	}
	if d := a.expiresAt.Sub(exp).Abs(); d > time.Second {
		t.Fatalf("expiresAt=%s want ~%s (delta %s)", a.expiresAt, exp, d)
	}
}

func TestLoadFallsBackToExpiredField(t *testing.T) {
	dir := t.TempDir()
	exp := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	// non-JWT access token → fall back to expired field
	body := map[string]any{
		"access_token":  "not-a-jwt",
		"refresh_token": "rt-test",
		"email":         "fallback@x.ai",
		"expired":       exp.Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(body, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "b.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(filepath.Join(dir, "*.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := pool.accounts[0]
	if a.needsRefresh() {
		t.Fatal("should not need refresh")
	}
	if d := a.expiresAt.Sub(exp).Abs(); d > time.Second {
		t.Fatalf("expiresAt=%s want %s", a.expiresAt, exp)
	}
}

func TestNeedsRefreshSkew(t *testing.T) {
	// Accounts more than refreshSkew from expiry must not need refresh.
	a := &Account{expiresAt: time.Now().Add(10 * time.Minute)}
	if a.needsRefresh() {
		t.Fatal("10min left should not need refresh")
	}
	// Within skew → needs refresh
	b := &Account{expiresAt: time.Now().Add(3 * time.Minute)}
	if !b.needsRefresh() {
		t.Fatal("3min left (<5min skew) should need refresh")
	}
	// Already expired
	c := &Account{expiresAt: time.Now().Add(-time.Minute)}
	if !c.needsRefresh() {
		t.Fatal("expired should need refresh")
	}
}

func TestRefreshSkippedSentinel(t *testing.T) {
	if errRefreshSkipped == nil {
		t.Fatal("nil sentinel")
	}
	if !errors.Is(errRefreshSkipped, errRefreshSkipped) {
		t.Fatal("errors.Is self")
	}
}
