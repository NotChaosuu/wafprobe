// Package client sends requests with a persona's full fingerprint (TLS ClientHello,
// HTTP/2 settings, header order) via bogdanfinn/tls-client, and reads back what
// was actually negotiated.
package client

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/ja4"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"github.com/klauspost/compress/zstd"
)

// Options tunes the client. The second group are hunt's per-axis mutations.
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
	ExtraHeaders      []persona.HeaderField // ordered: appended after the persona defaults, in order
	DropHeaders       []string
	StripCookies      bool
	MethodOverride    string

	Proxy *url.URL // build with ParseProxy
}

// Client issues persona-fingerprinted requests, one fresh handshake per request.
type Client struct {
	p    persona.Persona
	opts Options
}

// New returns a Client for the persona.
func New(p persona.Persona, opts Options) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 64 * 1024
	}
	return &Client{p: p, opts: opts}
}

// Wire is what the connection actually negotiated, so hunt can spot mutations
// the stack ignored (e.g. a preset forcing ALPN back to h2).
type Wire struct {
	HTTP2       bool
	ALPN        string
	TLSVersion  uint16
	Method      string
	SNIOmitted  bool
	SpecMutated bool     // the ClientHello was rewritten for an ALPN/TLS/SNI mutation
	HeaderNames []string // lowercased request header names actually sent, in order
	JA4H        string   // JA4H fingerprint of the request that was sent
}

// Result is a normalized response plus the negotiated wire state.
type Result struct {
	Status  int
	Header  http.Header
	Cookies []*http.Cookie
	Body    []byte
	Wire    Wire
}

// Do issues one request and returns the decoded response and wire state.
func (c *Client) Do(ctx context.Context, method, rawURL string, body []byte, cookie string) (*Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	// stock personas are plain Go clients: use crypto/tls directly. Real Go
	// fingerprint, and avoids a utls HelloGolang cert-verify quirk.
	if c.p.Stock {
		return c.stockDo(ctx, method, rawURL, body, cookie)
	}

	profile, specMutated, sniOmitted := c.buildProfile()

	timeoutMs := int(c.opts.Timeout / time.Millisecond)
	if timeoutMs <= 0 {
		timeoutMs = 15000
	}
	clientOpts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTimeoutMilliseconds(timeoutMs),
		// transport would otherwise add accept-encoding: gzip and auto-decode,
		// so we set it from the persona and decompress ourselves
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true}),
	}
	// browsers shuffle extension order per connection; JA4 is order-invariant
	if c.p.Randomized {
		clientOpts = append(clientOpts, tls_client.WithRandomTLSExtensionOrder())
	}
	// no cert validation: this probes WAF behaviour, it's not a secure channel.
	// also dodges a utls verify quirk on some ECDSA certs that looks like a block
	clientOpts = append(clientOpts, tls_client.WithInsecureSkipVerify())
	if c.opts.Proxy != nil {
		clientOpts = append(clientOpts, tls_client.WithProxyUrl(c.opts.Proxy.String()))
	}
	if sni := c.opts.SNIOverride; sni != "" && sni != "-" {
		clientOpts = append(clientOpts, tls_client.WithServerNameOverwrite(sni))
	}

	tc, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("build tls client: %w", err)
	}
	defer tc.CloseIdleConnections()

	if method == "" {
		method = fhttp.MethodGet
	}
	if c.opts.MethodOverride != "" {
		method = c.opts.MethodOverride
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := fhttp.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	header, pairs := c.buildHeaders(cookie)
	req.Header = header

	resp, err := tc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	decoded, err := readAndDecode(resp.Body, resp.Header.Get("Content-Encoding"), c.opts.MaxBodyBytes)
	if err != nil {
		return nil, err
	}

	order := make([]string, len(pairs))
	for i, p := range pairs {
		order[i] = p.Name
	}
	w := Wire{
		Method:      method,
		SNIOmitted:  sniOmitted,
		SpecMutated: specMutated,
		HeaderNames: order,
		HTTP2:       resp.ProtoMajor == 2,
		JA4H:        ja4h(method, resp.ProtoMajor == 2, pairs, cookie),
	}
	if resp.TLS != nil {
		w.ALPN = resp.TLS.NegotiatedProtocol
		w.TLSVersion = resp.TLS.Version
	}

	return &Result{
		Status:  resp.StatusCode,
		Header:  toStdHeader(resp.Header),
		Cookies: toStdCookies(resp.Cookies()),
		Body:    decoded,
		Wire:    w,
	}, nil
}

// stockDo uses net/http + crypto/tls, so resp.TLS gives exact ALPN/version read-back.
func (c *Client) stockDo(ctx context.Context, method, rawURL string, body []byte, cookie string) (*Result, error) {
	cfg := &cryptotls.Config{InsecureSkipVerify: true} //nolint:gosec — a WAF prober, not a secure channel
	if c.opts.MinTLSVersion != 0 {
		cfg.MinVersion = c.opts.MinTLSVersion
	}
	if c.opts.MaxTLSVersion != 0 {
		cfg.MaxVersion = c.opts.MaxTLSVersion
	}
	sniOmitted := false
	switch {
	case c.opts.SNIOverride == "-":
		cfg.ServerName = ""
		cfg.InsecureSkipVerify = true
		sniOmitted = true
	case c.opts.SNIOverride != "":
		cfg.ServerName = c.opts.SNIOverride
	}
	if c.opts.ALPNOverride != nil {
		cfg.NextProtos = c.opts.ALPNOverride
	}

	tr := &http.Transport{
		TLSClientConfig:    cfg,
		DisableKeepAlives:  true,
		DisableCompression: true, // own Accept-Encoding + decode ourselves
		// with an ALPN override, ForceAttemptHTTP2 would re-append http/1.1
		ForceAttemptHTTP2: c.opts.ALPNOverride == nil,
	}
	if c.opts.Proxy != nil {
		tr.Proxy = http.ProxyURL(c.opts.Proxy)
	}
	if sniOmitted {
		// http.Transport refills empty ServerName from the host, so do the handshake
		// ourselves. keep baseline NextProtos so only SNI changes.
		dialer := &net.Dialer{Timeout: c.opts.Timeout}
		hsCfg := cfg.Clone()
		hsCfg.ServerName = ""
		if len(hsCfg.NextProtos) == 0 {
			hsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, derr := dialer.DialContext(ctx, network, addr)
			if derr != nil {
				return nil, derr
			}
			tconn := cryptotls.Client(raw, hsCfg)
			if herr := tconn.HandshakeContext(ctx); herr != nil {
				_ = raw.Close()
				return nil, herr
			}
			return tconn, nil
		}
	}
	hc := &http.Client{Transport: tr, Timeout: c.opts.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	if method == "" {
		method = http.MethodGet
	}
	if c.opts.MethodOverride != "" {
		method = c.opts.MethodOverride
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	header, pairs := c.buildHeaders(cookie)
	order := make([]string, 0, len(pairs))
	for k, v := range header {
		if k == fhttp.HeaderOrderKey || k == fhttp.PHeaderOrderKey {
			continue
		}
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	for _, p := range pairs {
		order = append(order, p.Name)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	decoded, err := readAndDecode(resp.Body, resp.Header.Get("Content-Encoding"), c.opts.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	w := Wire{
		Method:      method,
		SNIOmitted:  sniOmitted,
		SpecMutated: c.opts.MinTLSVersion != 0 || c.opts.MaxTLSVersion != 0 || c.opts.ALPNOverride != nil || sniOmitted,
		HeaderNames: order,
		HTTP2:       resp.ProtoMajor == 2,
		JA4H:        ja4h(method, resp.ProtoMajor == 2, pairs, cookie),
	}
	if resp.TLS != nil {
		w.ALPN = resp.TLS.NegotiatedProtocol
		w.TLSVersion = resp.TLS.Version
	}
	return &Result{
		Status:  resp.StatusCode,
		Header:  resp.Header,
		Cookies: resp.Cookies(),
		Body:    decoded,
		Wire:    w,
	}, nil
}

// buildProfile applies ALPN/TLS-version/SNI mutations to a copy of the persona's
// ClientHello, keeping the HTTP/2 fingerprint. ok=false when the spec can't be
// built (HelloGolang); third result is whether SNI was omitted.
func (c *Client) buildProfile() (profiles.ClientProfile, bool, bool) {
	base := c.p.Profile
	sniWanted := c.opts.SNIOverride == "-"
	needCustom := c.opts.ALPNOverride != nil || c.opts.MinTLSVersion != 0 || c.opts.MaxTLSVersion != 0 || sniWanted
	if !needCustom {
		return base, false, false
	}

	// HelloGolang has no offline spec, so no TLS-layer mutations for it
	spec, err := base.GetClientHelloSpec()
	if err != nil {
		return base, false, false
	}
	if c.opts.ALPNOverride != nil {
		applyALPN(&spec, c.opts.ALPNOverride)
	}
	if v := targetTLSVersion(c.opts.MinTLSVersion, c.opts.MaxTLSVersion); v != 0 {
		applyTLSVersion(&spec, v)
	}
	if sniWanted {
		removeExtension(&spec, func(e tls.TLSExtension) bool {
			_, ok := e.(*tls.SNIExtension)
			return ok
		})
	}
	baseID := base.GetClientHelloId()
	id := tls.ClientHelloID{
		Client:      baseID.Client + "-mut",
		Version:     baseID.Version,
		SpecFactory: func() (tls.ClientHelloSpec, error) { return spec, nil },
	}
	custom := profiles.NewClientProfile(
		id,
		base.GetSettings(), base.GetSettingsOrder(), base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(), base.GetPriorities(), base.GetHeaderPriority(),
		base.GetStreamID(), base.GetAllowHTTP(),
		base.GetHttp3Settings(), base.GetHttp3SettingsOrder(), base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(), base.GetHttp3SendGreaseFrames(),
	)
	return custom, true, sniWanted
}

// buildHeaders returns persona defaults plus mutations, and the lowercased wire order.
func (c *Client) buildHeaders(cookie string) (fhttp.Header, []ja4.Header) {
	order := make([]string, 0, len(c.p.Headers)+4)
	values := map[string]string{}
	add := func(name, value string) {
		key := strings.ToLower(name)
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = value
	}
	for _, h := range c.p.Headers {
		add(h.Name, h.Value)
	}
	if c.opts.UserAgentOverride != "" {
		add("user-agent", c.opts.UserAgentOverride)
	}
	for _, h := range c.opts.ExtraHeaders {
		add(h.Name, h.Value)
	}
	if cookie != "" && !c.opts.StripCookies {
		add("cookie", cookie)
	}
	// drop after merge so persona defaults can be removed too
	drop := map[string]bool{}
	for _, d := range c.opts.DropHeaders {
		drop[strings.ToLower(d)] = true
	}
	if c.opts.StripCookies {
		drop["cookie"] = true
	}

	header := fhttp.Header{}
	orderKey := make([]string, 0, len(order))
	pairs := make([]ja4.Header, 0, len(order))
	for _, k := range order {
		if drop[k] {
			continue
		}
		header[k] = []string{values[k]}
		orderKey = append(orderKey, k)
		pairs = append(pairs, ja4.Header{Name: k, Value: values[k]})
	}
	header[fhttp.HeaderOrderKey] = orderKey
	return header, pairs
}

// ja4h computes the JA4H fingerprint of the request that was sent.
func ja4h(method string, http2 bool, pairs []ja4.Header, cookie string) string {
	var cookies []ja4.Cookie
	for _, kv := range parseCookiePairs(cookie) {
		cookies = append(cookies, ja4.Cookie{Name: kv[0], Value: kv[1]})
	}
	return ja4.JA4H(ja4.HTTPRequest{
		Method:  method,
		HTTP2:   http2,
		Headers: pairs,
		Cookies: cookies,
	})
}

func parseCookiePairs(cookie string) [][2]string {
	if cookie == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out = append(out, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	return out
}

func applyALPN(spec *tls.ClientHelloSpec, protos []string) {
	if len(protos) == 0 {
		removeExtension(spec, func(e tls.TLSExtension) bool {
			_, ok := e.(*tls.ALPNExtension)
			return ok
		})
		return
	}
	for _, e := range spec.Extensions {
		if a, ok := e.(*tls.ALPNExtension); ok {
			a.AlpnProtocols = protos
			return
		}
	}
	// base has no ALPN ext, add one
	spec.Extensions = append(spec.Extensions, &tls.ALPNExtension{AlpnProtocols: protos})
}

func applyTLSVersion(spec *tls.ClientHelloSpec, version uint16) {
	for _, e := range spec.Extensions {
		if sv, ok := e.(*tls.SupportedVersionsExtension); ok {
			kept := sv.Versions[:0]
			for _, v := range sv.Versions {
				if isGREASE(v) || v == version {
					kept = append(kept, v)
				}
			}
			if len(kept) == 0 {
				kept = append(kept, version)
			}
			sv.Versions = kept
		}
	}
	spec.TLSVersMin = version
	spec.TLSVersMax = version
}

func removeExtension(spec *tls.ClientHelloSpec, match func(tls.TLSExtension) bool) {
	kept := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		if match(e) {
			continue
		}
		kept = append(kept, e)
	}
	spec.Extensions = kept
}

func targetTLSVersion(min, max uint16) uint16 {
	if max != 0 {
		return max
	}
	return min
}

func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0x00ff)
}

// readAndDecode returns up to MaxBodyBytes of decoded body. We advertise browser
// encodings, so gzip/deflate/br/zstd has to be handled here.
func readAndDecode(body io.Reader, contentEncoding string, maxBody int64) ([]byte, error) {
	const compressedCap = 4 << 20 // read at most 4 MiB of compressed bytes
	raw, err := io.ReadAll(io.LimitReader(body, compressedCap))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	var dec io.Reader = bytes.NewReader(raw)
	switch enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, e := gzip.NewReader(bytes.NewReader(raw))
		if e != nil {
			return raw[:capLen(raw, maxBody)], nil
		}
		dec = zr
	case "deflate":
		dec = flate.NewReader(bytes.NewReader(raw))
	case "br":
		dec = brotli.NewReader(bytes.NewReader(raw))
	case "zstd":
		zr, e := zstd.NewReader(bytes.NewReader(raw))
		if e != nil {
			return raw[:capLen(raw, maxBody)], nil
		}
		defer zr.Close()
		dec = zr
	default:
		return raw[:capLen(raw, maxBody)], nil
	}
	out, err := io.ReadAll(io.LimitReader(dec, maxBody))
	if err != nil && len(out) == 0 {
		// decode failed, return raw so detectors still get headers/status
		return raw[:capLen(raw, maxBody)], nil
	}
	return out, nil
}

func capLen(b []byte, max int64) int {
	if max > 0 && int64(len(b)) > max {
		return int(max)
	}
	return len(b)
}

// fhttp -> stdlib, detect wants stdlib types

func toStdHeader(h fhttp.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
	}
	return out
}

func toStdCookies(cs []*fhttp.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(cs))
	for _, c := range cs {
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	return out
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
