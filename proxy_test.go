package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBuildTransport(t *testing.T) {
	cases := []struct {
		name         string
		proxy        string
		wantErr      bool
		wantProxyNil bool // socks5 clears transport.Proxy; http/empty keep it set
	}{
		{"empty", "", false, false},
		{"http", "http://127.0.0.1:8080", false, false},
		{"https", "https://127.0.0.1:8080", false, false},
		{"socks5", "socks5://127.0.0.1:1080", false, true},
		{"socks5h auth", "socks5h://u:p@127.0.0.1:1080", false, true},
		{"socks5 default port", "socks5://127.0.0.1", false, true},
		{"bad scheme", "ftp://127.0.0.1:1080", true, false},
		{"garbage", "://not a url", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, err := buildTransport(c.proxy)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := tr.Proxy == nil; got != c.wantProxyNil {
				t.Errorf("transport.Proxy nil = %v, want %v", got, c.wantProxyNil)
			}
			if tr.DialContext == nil {
				t.Errorf("transport.DialContext unexpectedly nil")
			}
		})
	}
}

// TestSocks5DialRoutesThroughProxy proves the SOCKS5 path installs a dialer that
// connects to the proxy address, not the target. A local listener stands in for
// the SOCKS5 server; if the dialer is wired correctly it connects to us first.
// No external network is needed, and a buggy (direct) dial would hit a
// unroutable TEST-NET address instead of our listener.
func TestSocks5DialRoutesThroughProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			select {
			case accepted <- struct{}{}:
			default:
			}
			c.Close()
		}
	}()

	tr, err := buildTransport("socks5://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Target is irrelevant and intentionally unroutable (TEST-NET-2). The SOCKS5
	// dialer must connect to our listener before ever reaching it.
	_, _ = tr.DialContext(ctx, "tcp", "198.51.100.1:443")

	select {
	case <-accepted:
		// success: traffic was routed to the proxy address
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 dialer did not connect to the proxy listener; target may have been dialed directly")
	}
}
