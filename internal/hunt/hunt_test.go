package hunt

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// fakeTLSServer returns an HTTPS test server that delegates to gate(). When
// gate returns a non-empty reason, the server replies 403 with a CF-style
// challenge body; otherwise 200 "ok".
func fakeTLSServer(t *testing.T, gate func(r *http.Request) string) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason := gate(r); reason != "" {
			w.Header().Set("CF-Ray", "fake-ray")
			w.Header().Set("CF-Mitigated", "challenge")
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<title>Just a moment...</title> Cloudflare blocked: "+reason)
			return
		}
		w.Header().Set("CF-Ray", "ok-ray")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return srv
}

// TestHunt_UAGate: gate blocks Mozilla / Go-http / python but allows
// Googlebot. Hunt must classify user-agent as a checked axis.
func TestHunt_UAGate(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string {
		ua := r.UserAgent()
		if strings.Contains(ua, "Go-http") || strings.Contains(ua, "python") {
			return "bad UA"
		}
		if strings.Contains(ua, "Googlebot") {
			return ""
		}
		// Block default browsers too so the baseline gets blocked.
		if strings.Contains(ua, "Mozilla") {
			return "bad browser UA"
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona:            p,
		InsecureSkipVerify: true,
		Concurrency:        4,
		PerProbeTimeout:    3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rep.BaselineOutcome != OutcomeBlocked {
		t.Fatalf("expected baseline blocked, got %s (status=%d)", rep.BaselineOutcome, rep.BaselineStatus)
	}
	found := false
	for _, a := range rep.Findings.Checks {
		if a == "user-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'user-agent' in Checks, got %v", rep.Findings.Checks)
	}
	if len(rep.Findings.PassingMutations) == 0 {
		t.Errorf("expected some PassingMutations, got none. Summary: %s", rep.Findings.Summary)
	}
}

// TestHunt_TLSVersionGate uses go-stdlib because utls presets hardcode
// supported_versions; tls-version mutations only affect the stock-TLS path.
func TestHunt_TLSVersionGate(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if r.TLS != nil && r.TLS.Version == tls.VersionTLS13 {
			return "TLS 1.3 not allowed"
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("go-stdlib")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona:            p,
		InsecureSkipVerify: true,
		Concurrency:        4,
		PerProbeTimeout:    3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// go-stdlib negotiates 1.3 by default → blocked. The "force TLS 1.2"
	// mutation must flip it.
	if rep.BaselineOutcome != OutcomeBlocked {
		t.Logf("baseline outcome=%s (acceptable if 1.2 was negotiated)", rep.BaselineOutcome)
	}

	var tls12Passed bool
	for _, res := range rep.Results {
		if res.Mutation.Name == "force TLS 1.2" && res.Outcome == OutcomePass {
			tls12Passed = true
		}
	}
	if !tls12Passed {
		t.Errorf("expected 'force TLS 1.2' mutation to pass the TLS 1.3 gate on go-stdlib; got results:")
		for _, res := range rep.Results {
			if res.Mutation.Axis == "tls-version" {
				t.Logf("  %s → %s (status=%d, err=%s)", res.Mutation.Name, res.Outcome, res.Status, res.Error)
			}
		}
	}
}

// TestHunt_HeaderGate: gate requires X-Real-IP header.
func TestHunt_HeaderGate(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if r.Header.Get("X-Real-IP") == "" {
			return "missing X-Real-IP"
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona:            p,
		InsecureSkipVerify: true,
		Concurrency:        4,
		PerProbeTimeout:    3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var xrealipPassed bool
	for _, res := range rep.Results {
		if res.Mutation.Name == "add X-Real-IP: 127.0.0.1" && res.Outcome == OutcomePass {
			xrealipPassed = true
		}
	}
	if !xrealipPassed {
		t.Errorf("expected 'add X-Real-IP' mutation to flip outcome, didn't")
	}
}

// TestHunt_NoGate: open server. Baseline passes, no axis is reported as checked.
func TestHunt_NoGate(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string { return "" })
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona:            p,
		InsecureSkipVerify: true,
		Concurrency:        4,
		PerProbeTimeout:    3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BaselineOutcome != OutcomePass {
		t.Fatalf("baseline should pass an open server, got %s", rep.BaselineOutcome)
	}
	if !strings.Contains(rep.Findings.Summary, "passes with baseline") {
		t.Errorf("summary should indicate baseline passed, got %q", rep.Findings.Summary)
	}
}

// TestHunt_AllBlocked: every probe blocked; analyzer should report so.
func TestHunt_AllBlocked(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string {
		return "hard block"
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona:            p,
		InsecureSkipVerify: true,
		Concurrency:        4,
		PerProbeTimeout:    3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BaselineOutcome != OutcomeBlocked {
		t.Fatalf("baseline should block on hard-block gate, got %s", rep.BaselineOutcome)
	}
	if len(rep.Findings.PassingMutations) != 0 {
		t.Errorf("expected 0 passing mutations, got %d", len(rep.Findings.PassingMutations))
	}
	if !strings.Contains(rep.Findings.Summary, "no mutation passed") {
		t.Errorf("summary should flag 'no mutation passed', got %q", rep.Findings.Summary)
	}
}

func TestOutcomeString(t *testing.T) {
	cases := map[Outcome]string{
		OutcomePass:    "pass",
		OutcomeBlocked: "block",
		OutcomeError:   "err",
		OutcomeUnknown: "?",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("Outcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

func TestAllMutationsAreDistinct(t *testing.T) {
	seen := map[string]struct{}{}
	for _, m := range AllMutations() {
		if _, dup := seen[m.Name]; dup {
			t.Errorf("duplicate mutation name %q", m.Name)
		}
		seen[m.Name] = struct{}{}
		if m.Axis == "" {
			t.Errorf("mutation %q has empty axis", m.Name)
		}
		if m.Apply == nil {
			t.Errorf("mutation %q has nil Apply", m.Name)
		}
	}
}
