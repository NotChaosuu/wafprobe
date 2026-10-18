package client

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// wireRecord is what the server actually received.
type wireRecord struct {
	UA     string
	Proto  string // "HTTP/2.0" or "HTTP/1.1"
	SNI    string
	Method string
	HasAE  bool // Accept-Encoding present
	HasAL  bool // Accept-Language present
	GotCap bool
}

// newRecordingServer: HTTPS+h2 server that records the last request, optionally gzipping.
func newRecordingServer(t *testing.T, gzipBody bool) (string, *wireRecord, func()) {
	t.Helper()
	rec := &wireRecord{}
	var mu sync.Mutex
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		rec.UA = r.UserAgent()
		rec.Proto = r.Proto
		rec.Method = r.Method
		rec.HasAE = r.Header.Get("Accept-Encoding") != ""
		rec.HasAL = r.Header.Get("Accept-Language") != ""
		rec.GotCap = true
		if r.TLS != nil {
			rec.SNI = r.TLS.ServerName
		}
		mu.Unlock()

		body := "pong hello world"
		if gzipBody && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv.URL, rec, srv.Close
}

func TestNewDefaultsAreSane(t *testing.T) {
	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{})
	if c.opts.Timeout == 0 {
		t.Errorf("expected non-zero default timeout")
	}
	if c.opts.MaxBodyBytes == 0 {
		t.Errorf("expected non-zero default MaxBodyBytes")
	}
}

// every persona round-trips; browser personas get h2 and their headers on the wire
func TestEndToEndAllPersonas(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()

	for _, p := range persona.All() {
		t.Run(p.ID, func(t *testing.T) {
			c := New(p, Options{InsecureSkipVerify: true, Timeout: 8 * time.Second})
			res, err := c.Do(context.Background(), "GET", url, nil, "")
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if res.Status != 200 {
				t.Errorf("status = %d want 200", res.Status)
			}
			if rec.UA != p.UserAgent {
				t.Errorf("server saw UA %q want %q", rec.UA, p.UserAgent)
			}
			if strings.TrimSpace(string(res.Body)) != "pong hello world" {
				t.Errorf("body = %q", string(res.Body))
			}
			if res.Wire.JA4H == "" {
				t.Errorf("expected a JA4H fingerprint")
			}
			if !p.Stock && !res.Wire.HTTP2 {
				t.Errorf("browser persona %s should negotiate HTTP/2, got %q", p.ID, rec.Proto)
			}
		})
	}
}

// A caller-set User-Agent overrides the persona default, on the wire.
func TestUserAgentOverride(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")
	c := New(p, Options{InsecureSkipVerify: true, UserAgentOverride: "custom-ua/1.0"})
	if _, err := c.Do(context.Background(), "GET", url, nil, ""); err != nil {
		t.Fatal(err)
	}
	if rec.UA != "custom-ua/1.0" {
		t.Errorf("server saw UA %q, override didn't reach the wire", rec.UA)
	}
}

// ALPN http/1.1-only downgrades the wire
func TestALPNMutationReachesWire(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")

	c := New(p, Options{InsecureSkipVerify: true})
	res, err := c.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Wire.HTTP2 || rec.Proto != "HTTP/2.0" {
		t.Fatalf("baseline should be h2, got wire.HTTP2=%v proto=%q", res.Wire.HTTP2, rec.Proto)
	}

	c2 := New(p, Options{InsecureSkipVerify: true, ALPNOverride: []string{"http/1.1"}})
	res2, err := c2.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Wire.HTTP2 || rec.Proto != "HTTP/1.1" {
		t.Errorf("ALPN http/1.1 must downgrade the wire: wire.HTTP2=%v proto=%q", res2.Wire.HTTP2, rec.Proto)
	}
}

// dropping Accept-Encoding removes it from the wire
func TestDropHeaderReachesWire(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")

	c := New(p, Options{InsecureSkipVerify: true})
	if _, err := c.Do(context.Background(), "GET", url, nil, ""); err != nil {
		t.Fatal(err)
	}
	if !rec.HasAE {
		t.Fatal("chrome persona should send Accept-Encoding by default")
	}
	c2 := New(p, Options{InsecureSkipVerify: true, DropHeaders: []string{"Accept-Encoding"}})
	if _, err := c2.Do(context.Background(), "GET", url, nil, ""); err != nil {
		t.Fatal(err)
	}
	if rec.HasAE {
		t.Error("drop Accept-Encoding did not remove it from the wire")
	}
}

// SNI omit sends empty ServerName
func TestSNIOmitReachesWire(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")
	c := New(p, Options{InsecureSkipVerify: true, SNIOverride: "-"})
	if _, err := c.Do(context.Background(), "GET", url, nil, ""); err != nil {
		t.Fatal(err)
	}
	if rec.SNI != "" {
		t.Errorf("SNI omit should send empty ServerName, server saw %q", rec.SNI)
	}
}

func TestMethodOverride(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")
	c := New(p, Options{InsecureSkipVerify: true, MethodOverride: "OPTIONS"})
	if _, err := c.Do(context.Background(), "GET", url, nil, ""); err != nil {
		t.Fatal(err)
	}
	if rec.Method != "OPTIONS" {
		t.Errorf("method override didn't reach the wire: %q", rec.Method)
	}
}

// gzip body comes back decoded
func TestGzipBodyDecompressed(t *testing.T) {
	url, _, cleanup := newRecordingServer(t, true)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest") // sends Accept-Encoding: gzip, ...
	c := New(p, Options{InsecureSkipVerify: true})
	res, err := c.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Body), "hello world") {
		t.Errorf("gzip body was not decompressed: %q", string(res.Body))
	}
}

// extra headers keep a stable order, else JA4H changes every run
func TestExtraHeaderOrderStable(t *testing.T) {
	url, _, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("chrome-latest")
	extra := []persona.HeaderField{
		{Name: "X-A1b2c3d4-A", Value: "1"},
		{Name: "X-A1b2c3d4-B", Value: "2"},
		{Name: "X-A1b2c3d4-Z", Value: "q"},
		{Name: "X-Kpsdk-Ct", Value: "tok"},
		{Name: "Content-Type", Value: "application/json"},
	}
	first := ""
	for i := 0; i < 8; i++ {
		c := New(p, Options{InsecureSkipVerify: true, ExtraHeaders: extra})
		res, err := c.Do(context.Background(), "GET", url, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = res.Wire.JA4H
		} else if res.Wire.JA4H != first {
			t.Fatalf("JA4H changed across identical requests (header order not stable): %s vs %s", first, res.Wire.JA4H)
		}
	}
}

// stock persona ALPN override reaches the wire. SNI can't be checked here,
// the test server is an IP literal and TLS never sends SNI to an IP.
func TestStockMutationsReachWire(t *testing.T) {
	url, rec, cleanup := newRecordingServer(t, false)
	defer cleanup()
	p, _ := persona.ByID("go-stdlib")

	c := New(p, Options{InsecureSkipVerify: true})
	base, err := c.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !base.Wire.HTTP2 {
		t.Fatalf("stock baseline should negotiate h2, got proto=%q", rec.Proto)
	}

	c2 := New(p, Options{InsecureSkipVerify: true, ALPNOverride: []string{"http/1.1"}})
	res2, err := c2.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Wire.HTTP2 || rec.Proto != "HTTP/1.1" {
		t.Errorf("stock ALPN http/1.1 should downgrade the wire: wire.HTTP2=%v proto=%q", res2.Wire.HTTP2, rec.Proto)
	}

	// SNI omit keeps baseline ALPN, so still h2
	c3 := New(p, Options{InsecureSkipVerify: true, SNIOverride: "-"})
	res3, err := c3.Do(context.Background(), "GET", url, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res3.Wire.SNIOmitted {
		t.Errorf("stock SNI-omit should report SNIOmitted")
	}
	if !res3.Wire.HTTP2 {
		t.Errorf("stock SNI-omit must keep h2 (change only the SNI axis), got proto=%q", rec.Proto)
	}
}

func TestUnsupportedScheme(t *testing.T) {
	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{Timeout: 2 * time.Second})
	_, err := c.Do(context.Background(), "GET", "ftp://example.com/nope", nil, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("expected 'unsupported scheme', got %v", err)
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

func TestContextCancellation(t *testing.T) {
	p, _ := persona.ByID("firefox-latest")
	c := New(p, Options{Timeout: 2 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Do(ctx, "GET", "https://example.com/", nil, "")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
