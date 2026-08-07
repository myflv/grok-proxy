package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
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
