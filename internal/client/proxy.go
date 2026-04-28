package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	xproxy "golang.org/x/net/proxy"
)

// ParseProxy accepts both URL form ([scheme://][user:pass@]host:port) and
// the IP-rotation 4-part form (host:port:user:pass). Default scheme is http;
// pass socks5:// or https:// explicitly when needed.
//
// Limitation: a 4-part password containing '@' is ambiguous with URL form
// and not supported — use URL form instead.
func ParseProxy(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	if strings.Contains(s, "@") || strings.Contains(s, "://") {
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL: %w", err)
		}
		if u.Host == "" {
			return nil, errors.New("proxy URL missing host")
		}
		return u, nil
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2:
		return url.Parse("http://" + s)
	case 4:
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		if host == "" || port == "" {
			return nil, errors.New("proxy host:port:user:pass — empty host or port")
		}
		built := url.URL{
			Scheme: "http",
			User:   url.UserPassword(user, pass),
			Host:   net.JoinHostPort(host, port),
		}
		return &built, nil
	default:
		return nil, fmt.Errorf("unrecognized proxy format %q (expected scheme://[user:pass@]host:port OR host:port:user:pass)", s)
	}
}

// dialThroughProxy returns a TCP connection to target via proxyURL.
// Supports HTTP CONNECT (http://, https://) and SOCKS5.
func dialThroughProxy(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, dialer, proxyURL, target)
	case "http", "https", "":
		return dialHTTPConnect(ctx, dialer, proxyURL, target)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

func dialSOCKS5(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	var auth *xproxy.Auth
	if u := proxyURL.User; u != nil {
		pw, _ := u.Password()
		auth = &xproxy.Auth{User: u.Username(), Password: pw}
	}
	d, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, &netDialer{dialer: dialer, ctx: ctx})
	if err != nil {
		return nil, fmt.Errorf("socks5 setup: %w", err)
	}
	type ctxDialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	if cd, ok := d.(ctxDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	return d.Dial("tcp", target)
}

// netDialer adapts *net.Dialer to the xproxy.Dialer interface.
type netDialer struct {
	dialer *net.Dialer
	ctx    context.Context
}

func (n *netDialer) Dial(network, addr string) (net.Conn, error) {
	return n.dialer.DialContext(n.ctx, network, addr)
}

func dialHTTPConnect(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyURL.Host, err)
	}

	hdr := make(http.Header)
	if u := proxyURL.User; u != nil {
		pw, _ := u.Password()
		creds := u.Username() + ":" + pw
		hdr.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	hdr.Set("Host", target)

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: hdr,
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT %s returned %d", proxyURL.Host, resp.StatusCode)
	}
	return conn, nil
}
