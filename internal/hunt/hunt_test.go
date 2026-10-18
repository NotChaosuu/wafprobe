package hunt

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// 50/50 random responses must come back Unstable. alternating counter keeps
// it deterministic at concurrency 1.
func TestHunt_NoisyRunIsUnstable(t *testing.T) {
	var n int64
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if atomic.AddInt64(&n, 1)%2 == 0 {
			return "random block"
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona: p, InsecureSkipVerify: true, Concurrency: 1, Repeats: 3,
		PerProbeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.NoiseFloor < 0.15 {
		t.Errorf("a 50/50 target should have a high noise floor, got %.2f", rep.NoiseFloor)
	}
	if !rep.Findings.Unstable {
		t.Errorf("a 50/50 target must be reported Unstable (noise=%.2f)", rep.NoiseFloor)
	}
	if len(rep.Findings.Checks) != 0 {
		t.Errorf("an unstable run must not attribute axes: %v", rep.Findings.Checks)
	}
}

// blocked baseline with noise only on the bypass path: median=0, max=0.33,
// still has to flag unstable.
func TestHunt_BlockedBaselineNoisyBypassIsUnstable(t *testing.T) {
	var n int64
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if !strings.Contains(r.UserAgent(), "Googlebot") {
			return "no googlebot" // baseline + all non-bypass cells: deterministic block
		}
		if atomic.AddInt64(&n, 1)%2 == 0 {
			return "random 403 on the bypass path" // the bypass cell flakes
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona: p, InsecureSkipVerify: true, Concurrency: 1, Repeats: 3,
		PerProbeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BaselineOutcome != OutcomeBlocked {
		t.Fatalf("baseline should be a deterministic block, got %s", rep.BaselineOutcome)
	}
	if rep.BaselineFlakeRate != 0 {
		t.Errorf("baseline flake should be 0 (blocked deterministically), got %.2f — the point is the OTHER signal must catch it", rep.BaselineFlakeRate)
	}
	if !rep.Findings.Unstable {
		t.Errorf("a noisy bypass path must flag the run unstable via max cell flake (noise=%.2f)", rep.NoiseFloor)
	}
}

// one blip (first request blocked) gets resampled to 6/7 and doesn't void the run.
func TestHunt_SingleBlipResampledNotUnstable(t *testing.T) {
	var n int64
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if atomic.AddInt64(&n, 1) == 1 {
			return "one-off blip"
		}
		return ""
	})
	defer srv.Close()

	p, _ := persona.ByID("chrome-latest")
	rep, err := Run(context.Background(), srv.URL, Options{
		Persona: p, InsecureSkipVerify: true, Concurrency: 1, Repeats: 3,
		PerProbeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Findings.Unstable {
		t.Errorf("a single blip must not void the run (noise=%.2f) — it should resample away", rep.NoiseFloor)
	}
	if rep.NoiseFloor >= 0.15 {
		t.Errorf("one blip should land below the 15%% floor after resampling, got %.2f", rep.NoiseFloor)
	}
}

// fakeTLSServer returns 403 with a CF-style challenge when gate gives a reason, else 200.
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

// TestHunt_UAGate: only Googlebot passes, so user-agent must be checked.
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

// TestHunt_TLSVersionGate: forced TLS version reaches the wire via supported_versions.
func TestHunt_TLSVersionGate(t *testing.T) {
	srv := fakeTLSServer(t, func(r *http.Request) string {
		if r.TLS != nil && r.TLS.Version == tls.VersionTLS13 {
			return "TLS 1.3 not allowed"
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

	// chrome negotiates 1.3 -> blocked; forcing 1.2 should flip it
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
	if !strings.Contains(rep.Findings.Summary, "no verified mutation passed") {
		t.Errorf("summary should flag 'no verified mutation passed', got %q", rep.Findings.Summary)
	}
}

// high noise floor withholds the verdict
func TestAnalyzeUnstableWithholdsVerdict(t *testing.T) {
	rep := &Report{
		Reachable:       true,
		BaselineOutcome: OutcomePass,
		NoiseFloor:      0.5,
		Persona:         persona.Persona{ID: "chrome-latest"},
		Results: []MutationResult{
			{Mutation: Mutation{Name: "add X-Real-IP", Axis: "headers"}, Outcome: OutcomeBlocked},
			{Mutation: Mutation{Name: "method: OPTIONS", Axis: "method"}, Outcome: OutcomeBlocked},
		},
	}
	f := Analyze(rep)
	if !f.Unstable {
		t.Fatal("50% noise floor must set Unstable")
	}
	if len(f.Checks) != 0 || len(f.Ignores) != 0 {
		t.Errorf("an unstable verdict must not attribute axes: checks=%v ignores=%v", f.Checks, f.Ignores)
	}
	if !strings.Contains(f.Summary, "unstable") {
		t.Errorf("summary should say the run is unstable: %q", f.Summary)
	}
}

// noisy run with a deterministic-block baseline still gets flagged
func TestAnalyzeBlockedBaselineNoisyCellsUnstable(t *testing.T) {
	rep := &Report{
		Reachable:         true,
		BaselineOutcome:   OutcomeBlocked, // deterministic — its own flake is 0
		BaselineFlakeRate: 0.0,
		NoiseFloor:        0.4, // driven by max per-cell disagreement
		Persona:           persona.Persona{ID: "chrome-latest"},
		Results: []MutationResult{
			{Mutation: Mutation{Name: "UA: Googlebot", Axis: "user-agent"}, Outcome: OutcomePass, Samples: 3, Agree: 2},
		},
	}
	f := Analyze(rep)
	if !f.Unstable {
		t.Fatal("a noisy run must be Unstable even with a deterministically-blocked baseline")
	}
}

// maxCellFlake picks up a single split cell
func TestMaxCellFlake(t *testing.T) {
	results := []MutationResult{
		{Samples: 3, Agree: 3}, // 0.00
		{Samples: 3, Agree: 2}, // 0.33
		{Samples: 3, Agree: 3}, // 0.00
	}
	if got := maxCellFlake(results); got < 0.32 || got > 0.34 {
		t.Errorf("max cell flake = %.2f, want ~0.33 (a single split cell must show)", got)
	}
	if maxCellFlake(nil) != 0 {
		t.Error("no cells → 0")
	}
}

// A stable run still classifies normally.
func TestAnalyzeStableBaselineClassifies(t *testing.T) {
	rep := &Report{
		Reachable:         true,
		BaselineOutcome:   OutcomeBlocked,
		BaselineFlakeRate: 0.0,
		NoiseFloor:        0.0,
		Persona:           persona.Persona{ID: "chrome-latest"},
		Results: []MutationResult{
			{Mutation: Mutation{Name: "UA: Googlebot", Axis: "user-agent"}, Outcome: OutcomePass},
			{Mutation: Mutation{Name: "drop Accept", Axis: "headers"}, Outcome: OutcomeBlocked},
		},
	}
	f := Analyze(rep)
	if f.Unstable {
		t.Error("a 0% flake baseline must not be Unstable")
	}
	if !contains(f.Checks, "user-agent") {
		t.Errorf("user-agent flipped the block, should be checked: %v", f.Checks)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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
