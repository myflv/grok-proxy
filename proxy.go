package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

// buildTransport returns an http.Transport that routes outbound traffic through
// the given proxy URL. Supported schemes:
//   - http, https: HTTP CONNECT proxy (set via transport.Proxy)
//   - socks5, socks5h: SOCKS5 proxy, with optional user:pass auth taken from the URL
//
// An empty proxyStr returns a cloned default transport with no proxy override.
func buildTransport(proxyStr string) (*http.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxyStr == "" {
		return tr, nil
	}
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("parse proxy %q: %w", proxyStr, err)
	}
	switch u.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		// SOCKS5 cannot use transport.Proxy (HTTP CONNECT only); install a
		// custom dialer instead. x/net/proxy reads user:pass from u.User and
		// resolves domain names on the proxy side (so socks5 and socks5h
		// behave the same).
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %q: %w", proxyStr, err)
		}
		tr.Proxy = nil // don't also consult HTTP_PROXY/HTTPS_PROXY env
		tr.DialContext = dialContextFrom(d)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5, or socks5h)", u.Scheme)
	}
	log.Printf("[proxy] outbound via %s", proxyStr)
	return tr, nil
}

// dialContextFrom adapts a proxy.Dialer to the signature transport.DialContext
// expects. Dialers implementing proxy.ContextDialer (the SOCKS5 dialer does)
// are used directly so context cancellation is honored; others get a goroutine
// wrapper that closes a late connection on cancel.
func dialContextFrom(d proxy.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		type result struct {
			c   net.Conn
			err error
		}
		ch := make(chan result, 1)
		go func() {
			c, err := d.Dial(network, addr)
			ch <- result{c, err}
		}()
		select {
		case <-ctx.Done():
			go func() {
				if r := <-ch; r.c != nil {
					r.c.Close()
				}
			}()
			return nil, ctx.Err()
		case r := <-ch:
			return r.c, r.err
		}
	}
}
