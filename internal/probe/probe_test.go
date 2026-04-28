package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/persona"
)

func detectStub(vendor string, blocked bool) detect.Detection {
	layer := detect.LayerPass
	if blocked {
		layer = detect.LayerHTTP
	}
	return detect.Detection{Vendor: vendor, Layer: layer, Blocked: blocked, Confidence: "high"}
}

// fakeServer returns an HTTPS test server whose handler mimics a Cloudflare
// block for User-Agents that look like stock scripts.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.UserAgent()
		if contains(ua, "Go-http") || contains(ua, "python") {
			w.Header().Set("CF-Ray", "fake-ray")
			w.Header().Set("CF-Mitigated", "challenge")
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<title>Just a moment...</title> Checking your browser")
			return
		}
		// Pass-through: echo the UA back.
		w.Header().Set("CF-Ray", "ok-ray")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "pong")
	})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return srv
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRunAll_PassAndBlockedMix(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()

	r := NewRunner(Options{
		InsecureSkipVerify: true,
		RequestTimeout:     5 * time.Second,
		Concurrency:        2,
	})

	personas := persona.All()
	results, err := r.RunAll(context.Background(), srv.URL, personas)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(results) != len(personas) {
		t.Fatalf("want %d results, got %d", len(personas), len(results))
	}

	// fakeServer is a UA-only gate. Browser personas pass; stock-TLS
	// personas (go-stdlib, python-requests) get blocked.
	var browserPassed, stockBlocked int
	for _, res := range results {
		if res.Error != "" {
			t.Errorf("persona %s errored: %s", res.PersonaID, res.Error)
			continue
		}
		if res.Detection.Vendor != "cloudflare" {
			t.Errorf("persona %s: expected cloudflare detection, got %q", res.PersonaID, res.Detection.Vendor)
		}
		if res.Persona.UseStockTLS {
			if !res.Detection.Blocked {
				t.Errorf("stock-TLS persona %s should get blocked by the UA gate, but passed", res.PersonaID)
			}
			if res.Detection.Blocked {
				stockBlocked++
			}
		} else {
			if res.Detection.Blocked {
				t.Errorf("browser persona %s should pass but got blocked: %+v", res.PersonaID, res.Detection)
			}
			if res.Status == 200 {
				browserPassed++
			}
		}
	}
	if browserPassed == 0 {
		t.Errorf("expected at least one browser persona to pass")
	}
	if stockBlocked == 0 {
		t.Errorf("expected stock-TLS personas to be blocked by UA gate")
	}
}

func TestRunAll_BadTargetIsRejected(t *testing.T) {
	r := NewRunner(Options{})
	_, err := r.RunAll(context.Background(), "not a url", nil)
	if err == nil {
		t.Error("expected error for bad target")
	}
}

func TestRunAll_EmptyPersonasReturnsEmpty(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	r := NewRunner(Options{InsecureSkipVerify: true, RequestTimeout: 2 * time.Second})
	res, err := r.RunAll(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 results, got %d", len(res))
	}
}

func TestSummarize(t *testing.T) {
	rs := []Result{
		{Status: 200, Detection: detectStub("cloudflare", false)},
		{Status: 403, Detection: detectStub("cloudflare", true)},
		{Error: "dial failed"},
		{Status: 200, Detection: detectStub("akamai", false)},
	}
	s := Summarize("https://x", rs)
	if s.TotalPersonas != 4 {
		t.Errorf("total=%d want 4", s.TotalPersonas)
	}
	if s.Passed != 2 {
		t.Errorf("passed=%d want 2", s.Passed)
	}
	if s.Blocked != 1 {
		t.Errorf("blocked=%d want 1", s.Blocked)
	}
	if s.Errored != 1 {
		t.Errorf("errored=%d want 1", s.Errored)
	}
	if len(s.DetectedVendors) != 2 {
		t.Errorf("vendors=%v want 2", s.DetectedVendors)
	}
}

// TestContextCancellationAbortsRuns: Ctrl-C must not leak goroutines.
func TestContextCancellationAbortsRuns(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := NewRunner(Options{InsecureSkipVerify: true, RequestTimeout: 2 * time.Second})
	results, err := r.RunAll(ctx, srv.URL, persona.All())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	// At least one error is enough; we just need to verify the run aborted.
	errored := 0
	for _, r := range results {
		if r.Error != "" {
			errored++
		}
	}
	if errored == 0 {
		t.Errorf("expected at least one errored result after ctx cancel, got all clean")
	}
}
