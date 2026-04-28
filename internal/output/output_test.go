package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

func sampleResults() []probe.Result {
	firefox, _ := persona.ByID("firefox-latest")
	chrome, _ := persona.ByID("chrome-latest")
	return []probe.Result{
		{
			Persona:   firefox,
			PersonaID: "firefox-latest",
			Name:      "Firefox 120",
			StartedAt: time.Unix(1_700_000_000, 0),
			Duration:  45 * time.Millisecond,
			Status:    200,
			JA3Hash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Detection: detect.Detection{Vendor: "cloudflare", Layer: detect.LayerPass, Blocked: false, Signals: []string{"header:cf-ray=abc"}, Confidence: "high"},
		},
		{
			Persona:   chrome,
			PersonaID: "chrome-latest",
			Name:      "Chrome 120",
			StartedAt: time.Unix(1_700_000_001, 0),
			Duration:  78 * time.Millisecond,
			Status:    403,
			JA3Hash:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Detection: detect.Detection{Vendor: "cloudflare", Layer: detect.LayerChallenge, Blocked: true, Signals: []string{"header:cf-mitigated=challenge"}, Confidence: "high"},
		},
		{
			PersonaID: "go-stdlib",
			Name:      "Go net/http",
			Error:     "tls: connection refused",
			Detection: detect.Detection{Vendor: "", Layer: detect.LayerTLS, Blocked: true, Signals: []string{"transport:tls: connection refused"}, Confidence: "medium"},
		},
	}
}

func TestPrettyOutputContainsKeyFields(t *testing.T) {
	var buf bytes.Buffer
	err := Pretty(&buf, "https://example.com", sampleResults(), "0.1.0")
	if err != nil {
		t.Fatalf("Pretty: %v", err)
	}
	s := buf.String()
	mustContain := []string{
		"wafprobe v0.1.0",
		"target: https://example.com",
		"firefox-latest",
		"chrome-latest",
		"go-stdlib",
		"cloudflare",
		"pass",
		"challenge",
		"Summary:",
		"Vendors seen:",
	}
	for _, needle := range mustContain {
		if !strings.Contains(s, needle) {
			t.Errorf("pretty output missing %q; full output:\n%s", needle, s)
		}
	}
}

func TestPrettyOutputHasNoANSICodesForNonTerminal(t *testing.T) {
	// bytes.Buffer is not a *os.File so colourEnabled returns false.
	var buf bytes.Buffer
	_ = Pretty(&buf, "https://x", sampleResults(), "0.1.0")
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("pretty output to non-terminal should not contain ANSI escapes:\n%s", buf.String())
	}
}

func TestJSONOutputIsValid(t *testing.T) {
	var buf bytes.Buffer
	err := JSON(&buf, "https://example.com", sampleResults(), "0.1.0")
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var r JSONReport
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if r.Tool != "wafprobe" {
		t.Errorf("tool=%q want wafprobe", r.Tool)
	}
	if r.Version != "0.1.0" {
		t.Errorf("version=%q", r.Version)
	}
	if r.Target != "https://example.com" {
		t.Errorf("target=%q", r.Target)
	}
	if r.Summary.TotalPersonas != 3 {
		t.Errorf("total=%d want 3", r.Summary.TotalPersonas)
	}
	if r.Summary.Passed != 1 {
		t.Errorf("passed=%d want 1", r.Summary.Passed)
	}
	if r.Summary.Blocked != 1 {
		t.Errorf("blocked=%d want 1 (the chrome-latest CF challenge)", r.Summary.Blocked)
	}
	if r.Summary.Errored != 1 {
		t.Errorf("errored=%d want 1", r.Summary.Errored)
	}
	if len(r.Results) != 3 {
		t.Errorf("results len=%d", len(r.Results))
	}
}

func TestJSONOmitsPersonaStruct(t *testing.T) {
	// Persona is tagged json:"-" — only PersonaID + Name should appear.
	var buf bytes.Buffer
	_ = JSON(&buf, "https://x", sampleResults(), "0.1.0")
	if strings.Contains(buf.String(), "ClientHello") {
		t.Errorf("JSON unexpectedly includes utls internals:\n%s", buf.String())
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short: got %q", got)
	}
	if got := truncate("abcdefghij", 7); got != "abcd..." {
		t.Errorf("truncate long: got %q", got)
	}
}
