// Package apiproxy builds the HTTP client used for control-plane calls.
//
// Some hosts cannot reach api.ipvanish.com directly: Cloudflare answers with a
// block page for many datacenter ranges. Pointing the control plane at a proxy
// keeps switching working from there, while the tunnel itself stays direct.
package apiproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer returns an HTTP client whose requests leave through rawurl. An empty
// rawurl yields a plain client.
//
// Supported schemes: socks5, socks5h (remote name resolution) and http/https.
func Client(rawurl string, timeout time.Duration) (*http.Client, error) {
	if strings.TrimSpace(rawurl) == "" {
		return &http.Client{Timeout: timeout}, nil
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("apiproxy: parse %q: %w", rawurl, err)
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
	}

	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		base := &net.Dialer{Timeout: 15 * time.Second}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("apiproxy: socks5: %w", err)
		}
		ctxDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("apiproxy: socks5 dialer has no context support")
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return ctxDialer.DialContext(ctx, network, addr)
		}
	case "http", "https":
		transport.Proxy = http.ProxyURL(u)
	default:
		return nil, fmt.Errorf("apiproxy: unsupported scheme %q", u.Scheme)
	}

	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
