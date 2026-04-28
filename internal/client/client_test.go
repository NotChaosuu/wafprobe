package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// newLocalTLSServer returns an in-process HTTPS server that records the
// User-Agent of every request and echoes it back via X-Probe-Echo.
func newLocalTLSServer(t *testing.T) (url string, seenUA *[]string, cleanup func()) {
	t.Helper()

	uaList := &[]string{}
	var mu sync.Mutex

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*uaList = append(*uaList, r.UserAgent())
		mu.Unlock()
		w.Header().Set("X-Probe-Echo", r.UserAgent())
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "pong")
	})

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()

	return srv.URL, uaList, func() { srv.Close() }
}

func TestNewDefaultsAreSane(t *testing.T) {
	p, ok := persona.ByID("firefox-latest")
	if !ok {
		t.Fatal("firefox-latest must be registered")
	}
	c := New(p, Options{})
	if c.Timeout == 0 {
		t.Errorf("expected non-zero default timeout")
	}
	if c.Transport == nil {
		t.Errorf("expected Transport to be set")
	}
}

// TestEndToEnd_AllPersonas_RoundTrip catches utls preset regressions:
// every built-in persona must complete a handshake and round-trip a request.
func TestEndToEnd_AllPersonas_RoundTrip(t *testing.T) {
	url, seen, cleanup := newLocalTLSServer(t)
	defer cleanup()

	for _, p := range persona.All() {
		t.Run(p.ID, func(t *testing.T) {
			c := New(p, Options{InsecureSkipVerify: true, Timeout: 5 * time.Second})
			req, _ := http.NewRequest(http.MethodGet, url, nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("status = %d want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Probe-Echo"); got != p.UserAgent {
				t.Errorf("server saw UA %q want %q", got, p.UserAgent)
			}
			body, _ := io.ReadAll(resp.Body)
			if strings.TrimSpace(string(body)) != "pong" {
				t.Errorf("body = %q want 'pong'", string(body))
			}
		})
	}

	// Sanity: every persona's UA made it to the server.
	if len(*seen) != len(persona.All()) {
		t.Errorf("server saw %d requests, expected %d", len(*seen), len(persona.All()))
	}
}

// TestCallerSetUserAgentWins: caller-set UA is not overwritten by persona.
func TestCallerSetUserAgentWins(t *testing.T) {
	url, _, cleanup := newLocalTLSServer(t)
	defer cleanup()

	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{InsecureSkipVerify: true, Timeout: 5 * time.Second})
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "custom-ua/1.0")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Probe-Echo"); got != "custom-ua/1.0" {
		t.Errorf("server saw UA %q, caller's header was overwritten", got)
	}
}

// TestHTTPSSchemeRequired exercises the scheme-check error path.
func TestHTTPSSchemeRequired(t *testing.T) {
	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{Timeout: 2 * time.Second})
	req, _ := http.NewRequest(http.MethodGet, "ftp://example.com/nope", nil)
	_, err := c.Do(req)
	if err == nil {
		t.Fatal("expected error for non-http(s) scheme")
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Errorf("expected 'unsupported scheme' in %v", err)
	}
}

// TestPlainHTTPStillWorks: probes against plain HTTP targets must not panic.
func TestPlainHTTPStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe-Echo", r.UserAgent())
		_, _ = io.WriteString(w, "plain")
	}))
	defer srv.Close()

	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{Timeout: 5 * time.Second})

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Probe-Echo"); got != p.UserAgent {
		t.Errorf("UA mismatch: %q vs %q", got, p.UserAgent)
	}
}

// TestInspectTLSConnState: per-persona TLS state can be inspected post-dial.
func TestInspectTLSConnState(t *testing.T) {
	url, _, cleanup := newLocalTLSServer(t)
	defer cleanup()

	p, _ := persona.ByID("firefox-latest")
	rt := &personaTransport{
		persona: p,
		opts:    Options{InsecureSkipVerify: true, DialTimeout: 5 * time.Second},
		base:    &net.Dialer{Timeout: 5 * time.Second},
	}

	state, err := rt.InspectTLSConnState(context.Background(), url)
	if err != nil {
		t.Fatalf("InspectTLSConnState: %v", err)
	}
	if state.Version == 0 {
		t.Errorf("expected non-zero TLS version")
	}
	if state.CipherSuite == 0 {
		t.Errorf("expected a negotiated cipher suite")
	}
}

func TestSanitizeHost(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"https://example.com", false},
		{"https://example.com:8443", false},
		{"", true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("in=%q", c.in), func(t *testing.T) {
			_, err := SanitizeHost(c.in)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// TestRoundTripContextCancellation: cancellation aborts cleanly.
func TestRoundTripContextCancellation(t *testing.T) {
	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{Timeout: 2 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	_, err := c.Do(req)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
