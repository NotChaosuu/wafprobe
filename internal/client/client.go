// Package client provides an *http.Client whose TLS handshake matches a
// persona's utls ClientHelloID.
package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/persona"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Options tunes the client. The lower group are the per-probe axis-mutation
// knobs that hunt uses to vary one aspect of the connection at a time.
type Options struct {
	Timeout            time.Duration
	DialTimeout        time.Duration
	InsecureSkipVerify bool
	MaxBodyBytes       int64

	MinTLSVersion     uint16
	MaxTLSVersion     uint16
	ALPNOverride      []string // non-nil empty list suppresses ALPN
	SNIOverride       string   // "-" omits SNI entirely
	UserAgentOverride string
	ExtraHeaders      map[string]string
	DropHeaders       []string
	StripCookies      bool
	MethodOverride    string

	Proxy *url.URL // build with ParseProxy
}

// New returns an *http.Client configured for the persona. The persona's
// User-Agent is set automatically unless the caller already set one.
func New(p persona.Persona, opts Options) *http.Client {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 8 * time.Second
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 64 * 1024
	}
	rt := &personaTransport{
		persona: p,
		opts:    opts,
		base: &net.Dialer{
			Timeout:   opts.DialTimeout,
			KeepAlive: 30 * time.Second,
		},
	}
	return &http.Client{Transport: rt, Timeout: opts.Timeout}
}

// Connections are NOT reused across RoundTrips: every probe needs a fresh
// handshake so the WAF sees the persona's fingerprint.
type personaTransport struct {
	persona persona.Persona
	opts    Options
	base    *net.Dialer
}

func (t *personaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.applyRequestMutations(req)

	if req.URL.Scheme == "http" {
		return (&http.Transport{
			DialContext:       t.base.DialContext,
			DisableKeepAlives: true,
		}).RoundTrip(req)
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", req.URL.Scheme)
	}

	if t.persona.UseStockTLS {
		return t.roundTripStock(req)
	}

	conn, err := t.dialTLS(req.Context(), req.URL)
	if err != nil {
		return nil, err
	}
	switch conn.ConnectionState().NegotiatedProtocol {
	case "h2":
		return writeAndReadH2(req, conn)
	default:
		return writeAndRead(req, conn)
	}
}

// roundTripStock handles UseStockTLS personas via crypto/tls.
func (t *personaTransport) roundTripStock(req *http.Request) (*http.Response, error) {
	cfg := &tls.Config{InsecureSkipVerify: t.opts.InsecureSkipVerify} //nolint:gosec
	if t.opts.MinTLSVersion != 0 {
		cfg.MinVersion = t.opts.MinTLSVersion
	}
	if t.opts.MaxTLSVersion != 0 {
		cfg.MaxVersion = t.opts.MaxTLSVersion
	}
	if t.opts.ALPNOverride != nil {
		cfg.NextProtos = t.opts.ALPNOverride
	}
	if t.opts.SNIOverride != "" {
		if t.opts.SNIOverride == "-" {
			cfg.ServerName = ""
			cfg.InsecureSkipVerify = true
		} else {
			cfg.ServerName = t.opts.SNIOverride
		}
	}
	tr := &http.Transport{
		DialContext:       t.base.DialContext,
		TLSClientConfig:   cfg,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
	if t.opts.Proxy != nil {
		tr.Proxy = http.ProxyURL(t.opts.Proxy)
	}
	return tr.RoundTrip(req)
}

func (t *personaTransport) dialTLS(ctx context.Context, u *url.URL) (*utls.UConn, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid port %q", port)
	}

	raw, err := dialThroughProxy(ctx, t.base, t.opts.Proxy, net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	sni := host
	if t.opts.SNIOverride != "" {
		if t.opts.SNIOverride == "-" {
			sni = ""
		} else {
			sni = t.opts.SNIOverride
		}
	}
	alpn := []string{"h2", "http/1.1"}
	if t.opts.ALPNOverride != nil {
		alpn = t.opts.ALPNOverride
	}

	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: t.opts.InsecureSkipVerify || t.opts.SNIOverride == "-",
		NextProtos:         alpn,
	}
	if t.opts.MinTLSVersion != 0 {
		cfg.MinVersion = t.opts.MinTLSVersion
	}
	if t.opts.MaxTLSVersion != 0 {
		cfg.MaxVersion = t.opts.MaxTLSVersion
	}
	uc := utls.UClient(raw, cfg, t.persona.ClientHello)

	if dl, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(dl)
	} else if t.opts.DialTimeout > 0 {
		_ = uc.SetDeadline(time.Now().Add(t.opts.DialTimeout))
	}

	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	_ = uc.SetDeadline(time.Time{})
	return uc, nil
}

func writeAndRead(req *http.Request, conn *utls.UConn) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("nil request URL")
	}
	req = req.Clone(req.Context())
	req.ProtoMajor, req.ProtoMinor = 1, 1
	req.Proto = "HTTP/1.1"

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body = &connClosingBody{rc: resp.Body, conn: conn}
	return resp, nil
}

func writeAndReadH2(req *http.Request, conn *utls.UConn) (*http.Response, error) {
	tr := &http2.Transport{
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return conn, nil
		},
	}
	req = req.Clone(req.Context())
	req.ProtoMajor, req.ProtoMinor = 2, 0
	req.Proto = "HTTP/2.0"
	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("h2 roundtrip: %w", err)
	}
	resp.Body = &connClosingBody{rc: resp.Body, conn: conn}
	return resp, nil
}

func (t *personaTransport) applyRequestMutations(req *http.Request) {
	if t.opts.MethodOverride != "" {
		req.Method = t.opts.MethodOverride
	}
	switch {
	case t.opts.UserAgentOverride != "":
		req.Header.Set("User-Agent", t.opts.UserAgentOverride)
	case req.Header.Get("User-Agent") == "" && t.persona.UserAgent != "":
		req.Header.Set("User-Agent", t.persona.UserAgent)
	}
	for k, v := range t.opts.ExtraHeaders {
		req.Header.Set(k, v)
	}
	for _, h := range t.opts.DropHeaders {
		req.Header.Del(h)
	}
	if t.opts.StripCookies {
		req.Header.Del("Cookie")
	}
}

type connClosingBody struct {
	rc   io.ReadCloser
	conn *utls.UConn
}

func (b *connClosingBody) Read(p []byte) (int, error) { return b.rc.Read(p) }
func (b *connClosingBody) Close() error {
	_ = b.rc.Close()
	return b.conn.Close()
}

// ConnState exposes a subset of TLS state for test introspection.
type ConnState struct {
	NegotiatedProtocol string
	CipherSuite        uint16
	PeerCertCommonName string
	Version            uint16
}

// InspectTLSConnState performs a one-off dial and returns the negotiated state.
// Test helper.
func (t *personaTransport) InspectTLSConnState(ctx context.Context, target string) (ConnState, error) {
	u, err := url.Parse(target)
	if err != nil {
		return ConnState{}, err
	}
	uc, err := t.dialTLS(ctx, u)
	if err != nil {
		return ConnState{}, err
	}
	defer uc.Close()
	s := uc.ConnectionState()
	out := ConnState{
		NegotiatedProtocol: s.NegotiatedProtocol,
		CipherSuite:        s.CipherSuite,
		Version:            s.Version,
	}
	if len(s.PeerCertificates) > 0 {
		out.PeerCertCommonName = s.PeerCertificates[0].Subject.CommonName
	}
	return out, nil
}

// SanitizeHost validates a host string for CLI input.
func SanitizeHost(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty host")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("missing host")
	}
	return u.Host, nil
}

var _ = tls.VersionTLS12
