package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/hunt"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// send feeds messages through Update and returns the model and the last Cmd.
func send(t *testing.T, m model, msgs ...tea.Msg) (model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, msg := range msgs {
		var next tea.Model
		next, cmd = m.Update(msg)
		m = next.(model)
	}
	return m, cmd
}

func typed(s string) []tea.Msg {
	out := make([]tea.Msg, 0, len(s))
	for _, r := range s {
		out = append(out, key(string(r)))
	}
	return out
}

func sized(t *testing.T, w, h int) model {
	t.Helper()
	m, _ := send(t, newModel("test"), tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

// drain pumps a run's events into the model until the run leaves its screen.
func drain(t *testing.T, m model) model {
	t.Helper()
	for m.running() {
		select {
		case msg := <-m.events:
			m, _ = send(t, m, msg)
		case <-time.After(5 * time.Second):
			t.Fatal("run never finished")
		}
	}
	return m
}

// fakeReport is a hunt against a target that blocks unless the UA is Googlebot.
func fakeReport(target string, opts hunt.Options, noise float64) *hunt.Report {
	rep := &hunt.Report{
		Target: target, Persona: opts.Persona, Reachable: true, Method: "GET",
		BaselineOutcome: hunt.OutcomeBlocked, BaselineStatus: 403,
		BaselineDetection: detect.Detection{Vendor: "cloudflare", Blocked: true},
		Repeats:           opts.Repeats, NoiseFloor: noise,
	}
	for i, mu := range opts.Mutations {
		res := hunt.MutationResult{Mutation: mu, Status: 403, Outcome: hunt.OutcomeBlocked, Applied: true, Samples: 3, Agree: 3}
		if strings.Contains(mu.Name, "Googlebot") {
			res.Status, res.Outcome = 200, hunt.OutcomePass
		}
		rep.Results = append(rep.Results, res)
		if opts.Logger != nil {
			opts.Logger(i+1, len(opts.Mutations), res)
		}
	}
	rep.Findings = hunt.Analyze(rep)
	return rep
}

func TestNormalizeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":            "https://example.com",
		"  example.com/login  ":  "https://example.com/login",
		"http://localhost:8080":  "http://localhost:8080",
		"https://a.example/x?y=": "https://a.example/x?y=",
	} {
		if got, err := normalizeTarget(in); err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "   ", "ftp://example.com", "https://"} {
		if got, err := normalizeTarget(bad); err == nil {
			t.Errorf("normalizeTarget(%q) = %q, want an error", bad, got)
		}
	}
}

func TestHomeNavigation(t *testing.T) {
	m := sized(t, 100, 30)
	m, _ = send(t, m, key("down"), key("enter"))
	if m.scr != scrHuntForm {
		t.Fatalf("down+enter should open hunt, got screen %d", m.scr)
	}
	m, _ = send(t, m, key("esc"), key("4"))
	if m.scr != scrPersonas {
		t.Fatalf("4 should jump to personas, got screen %d", m.scr)
	}
	m, _ = send(t, m, key("esc"))
	_, cmd := send(t, m, key("q"))
	if cmd == nil {
		t.Fatal("q on home should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("q on home should return tea.Quit")
	}
}

func TestProbeFormValidatesBeforeSending(t *testing.T) {
	m := sized(t, 100, 30)
	called := false
	m.probeFn = func(context.Context, string, persona.Persona, int) probe.Result {
		called = true
		return probe.Result{}
	}
	m, _ = send(t, m, key("1"), key("enter"))
	if m.scr != scrProbeForm || m.pf.get("target").err == "" {
		t.Fatalf("an empty target must stay on the form with an error (screen %d)", m.scr)
	}

	// Deselect every persona: still no request.
	m, _ = send(t, m, typed("example.com")...)
	m, _ = send(t, m, key("tab"), key("a"), key("enter"))
	if m.scr != scrProbeForm || m.pf.get("personas").err == "" {
		t.Fatal("zero personas must stay on the form with an error")
	}
	if called {
		t.Fatal("nothing should be sent while the form is invalid")
	}
}

func TestProbeFlow(t *testing.T) {
	m := sized(t, 100, 30)
	m.probeFn = func(_ context.Context, target string, p persona.Persona, repeats int) probe.Result {
		r := probe.Result{Persona: p, PersonaID: p.ID, Name: p.Name, Status: 200, Samples: repeats, Agree: repeats,
			Detection: detect.Detection{Layer: detect.LayerPass}}
		if p.Stock {
			r.Status = 403
			r.Detection = detect.Detection{Vendor: "cloudflare", Layer: detect.LayerChallenge, Blocked: true, Signals: []string{"header:cf-mitigated"}}
		}
		return r
	}
	m, _ = send(t, m, key("1"))
	m, cmd := send(t, m, append(typed("example.com"), key("enter"))...)
	if m.scr != scrProbeRun || cmd == nil {
		t.Fatalf("enter on a valid form should start the run (screen %d)", m.scr)
	}
	if got := m.probeTarget; got != "https://example.com" {
		t.Errorf("target = %q, want the https:// form", got)
	}
	m = drain(t, m)
	if m.scr != scrProbeResult {
		t.Fatalf("finished run should show results, got screen %d", m.scr)
	}
	view := m.View()
	for _, want := range []string{"6 passed", "2 blocked", "cloudflare", "go-stdlib", "header:cf-mitigated"} {
		if !strings.Contains(view, want) {
			t.Errorf("results view is missing %q", want)
		}
	}

	// h carries the target into hunt, starting from a blocked persona.
	m, _ = send(t, m, key("h"))
	if m.scr != scrHuntForm {
		t.Fatalf("h should open the hunt form, got screen %d", m.scr)
	}
	if got := m.hf.get("target").value(); got != "https://example.com" {
		t.Errorf("hunt target = %q", got)
	}
	if p, _ := persona.ByID(m.hf.get("persona").value()); !p.Stock {
		t.Errorf("hunt should start from a blocked persona, got %s", p.ID)
	}
}

func TestHuntFlow(t *testing.T) {
	m := sized(t, 110, 40)
	var got hunt.Options
	m.huntFn = func(_ context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
		got = opts
		return fakeReport(target, opts, 0), nil
	}
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, append(typed("example.com/login"), key("enter"))...)
	if m.scr != scrHuntRun {
		t.Fatalf("enter should start the hunt, got screen %d", m.scr)
	}
	m = drain(t, m)
	if m.scr != scrHuntResult {
		t.Fatalf("finished hunt should show the verdict, got screen %d", m.scr)
	}
	if got.Persona.ID != "chrome-latest" || got.Repeats != 3 || len(got.Mutations) != len(hunt.AllMutations()) || got.Method != "GET" {
		t.Errorf("defaults not passed through: persona=%s repeats=%d mutations=%d method=%s",
			got.Persona.ID, got.Repeats, len(got.Mutations), got.Method)
	}
	content := m.huntResultView(m.contentW())
	for _, want := range []string{"blocked", "cloudflare", "checks", "user-agent", "Gets through", "curl", "answered differently from the baseline"} {
		if !strings.Contains(content, want) {
			t.Errorf("verdict is missing %q", want)
		}
	}
	var copied string
	m.copyFn = func(s string) error { copied = s; return nil }
	m, _ = send(t, m, key("c"))
	if !strings.Contains(copied, "Googlebot") || !strings.HasPrefix(copied, "curl") {
		t.Errorf("c should copy the bypass curl, got %q", copied)
	}

	// d re-runs with the other depth.
	m, _ = send(t, m, key("d"))
	m = drain(t, m)
	if len(got.Mutations) != len(hunt.DeepMutations()) || !m.huntRun.deep {
		t.Errorf("d should re-run deep, got %d mutations", len(got.Mutations))
	}
}

// An unstable run must not offer a bypass anywhere on the screen.
func TestHuntUnstableWithholdsBypass(t *testing.T) {
	m := sized(t, 110, 40)
	m.huntFn = func(_ context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
		return fakeReport(target, opts, 0.33), nil
	}
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, append(typed("example.com"), key("enter"))...)
	m = drain(t, m)
	content := m.huntResultView(m.contentW())
	if !m.rep.Findings.Unstable {
		t.Fatal("fixture should be unstable at a 33% noise floor")
	}
	if !strings.Contains(content, "Run unstable") {
		t.Error("unstable verdict not shown")
	}
	for _, banned := range []string{"Gets through", "curl ", "checks"} {
		if strings.Contains(content, banned) {
			t.Errorf("unstable verdict must not show %q", banned)
		}
	}
	copied := false
	m.copyFn = func(string) error { copied = true; return nil }
	m, _ = send(t, m, key("c"))
	if copied || strings.Contains(m.footer(), "copy curl") {
		t.Error("an unstable run must not offer or copy a bypass")
	}
}

func TestHuntUnreachable(t *testing.T) {
	m := sized(t, 110, 40)
	m.huntFn = func(_ context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
		return &hunt.Report{Target: target, Persona: opts.Persona, Reachable: false,
			Findings: hunt.Findings{Summary: "target is unreachable: connection refused. No axis was tested."}}, nil
	}
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, append(typed("127.0.0.1:1"), key("enter"))...)
	m = drain(t, m)
	content := m.huntResultView(m.contentW())
	if !strings.Contains(content, "Could not reach the target") || strings.Contains(content, "CHANGE") {
		t.Errorf("unreachable verdict should stand alone, got:\n%s", content)
	}
}

// Cancelling a run must drop whatever that run still delivers.
func TestCancelledRunIsIgnored(t *testing.T) {
	m := sized(t, 100, 30)
	release := make(chan struct{})
	m.huntFn = func(ctx context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
		<-release
		return fakeReport(target, opts, 0), nil
	}
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, append(typed("example.com"), key("enter"))...)
	old := m.events
	m, _ = send(t, m, key("esc"))
	if m.scr != scrHuntForm {
		t.Fatalf("esc should cancel back to the form, got screen %d", m.scr)
	}
	close(release)
	for i := 0; i < len(hunt.AllMutations())+1; i++ {
		m, _ = send(t, m, <-old)
	}
	if m.scr != scrHuntForm || m.rep != nil || m.nDone != 0 {
		t.Errorf("a cancelled run leaked into the UI: screen=%d rep=%v done=%d", m.scr, m.rep != nil, m.nDone)
	}
}

func TestBodyFieldFollowsMethod(t *testing.T) {
	m := sized(t, 100, 30)
	m, _ = send(t, m, key("2"))
	if strings.Contains(m.View(), "Body") {
		t.Error("GET should not offer a body field")
	}
	m.hf.focusID("method")
	m, _ = send(t, m, key("right"))
	if m.hf.get("method").value() != "POST" || !strings.Contains(m.View(), "Body") {
		t.Error("POST should reveal the body field")
	}
}

func TestHARFlow(t *testing.T) {
	dir := t.TempDir()
	har := filepath.Join(dir, "session.har")
	const doc = `{"log":{"version":"1.2","entries":[
	 {"request":{"method":"GET","url":"https://shop.example/","headers":[{"name":"User-Agent","value":"UA/1"}]}},
	 {"request":{"method":"POST","url":"https://shop.example/auth/login","headers":[{"name":"User-Agent","value":"UA/1"},{"name":"X-Token","value":"t"}],
	  "cookies":[{"name":"sid","value":"abc"}],"postData":{"mimeType":"application/json","text":"{\"u\":1}"}}}]}}`
	if err := os.WriteFile(har, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	m := sized(t, 100, 30)
	m, _ = send(t, m, key("3"))
	m, _ = send(t, m, append(typed(`"`+har+`"`), key("enter"))...)
	if m.scr != scrHARPick {
		t.Fatalf("a quoted path should open the picker, got screen %d (%s)", m.scr, m.harf.get("path").err)
	}
	m, _ = send(t, m, typed("login")...)
	if n := len(m.harMatches()); n != 1 {
		t.Fatalf("filter should leave 1 request, got %d", n)
	}
	m, _ = send(t, m, key("enter"))
	if m.scr != scrHARDone {
		t.Fatalf("enter should save the capture, got screen %d (%s)", m.scr, m.flash)
	}
	if _, err := os.Stat(filepath.Join(dir, "session-captured.json")); err != nil {
		t.Fatalf("capture file not written: %v", err)
	}

	var got hunt.Options
	m.huntFn = func(_ context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
		got = opts
		return fakeReport(target, opts, 0), nil
	}
	m, _ = send(t, m, key("h"))
	if m.scr != scrHuntForm || m.hf.get("target").value() != "https://shop.example/auth/login" || m.hf.get("method").value() != "POST" {
		t.Fatalf("h should prefill the hunt from the capture: target=%q method=%q", m.hf.get("target").value(), m.hf.get("method").value())
	}
	m, _ = send(t, m, key("enter"))
	m = drain(t, m)
	if got.Persona.UserAgent != "UA/1" || string(got.Body) != `{"u":1}` || got.Cookie == "" || len(got.ExtraHeaders) == 0 {
		t.Errorf("capture not replayed: ua=%q body=%q cookie=%q headers=%d", got.Persona.UserAgent, got.Body, got.Cookie, len(got.ExtraHeaders))
	}

	// Opening Hunt from the menu starts clean.
	m, _ = send(t, m, key("esc"), key("esc"), key("2"))
	if m.capture != nil {
		t.Error("a capture must not follow the user into a fresh hunt")
	}
}

// every screen fits its terminal, or the alt-screen wraps
func TestViewsFitTheTerminal(t *testing.T) {
	for _, size := range [][2]int{{minW, minH}, {80, 24}, {120, 40}, {200, 60}} {
		w, h := size[0], size[1]
		m := sized(t, w, h)
		m.probeFn = func(_ context.Context, _ string, p persona.Persona, n int) probe.Result {
			return probe.Result{Persona: p, PersonaID: p.ID, Status: 403, Samples: n, Agree: n - 1,
				Detection: detect.Detection{Vendor: "a-very-long-vendor-name-indeed", Layer: detect.LayerChallenge, Blocked: true,
					Signals: []string{"body:" + strings.Repeat("x", 300)}}}
		}
		m.huntFn = func(_ context.Context, target string, opts hunt.Options) (*hunt.Report, error) {
			return fakeReport(target, opts, 0), nil
		}
		check := func(name string, m model) {
			t.Helper()
			lines := strings.Split(m.View(), "\n")
			if len(lines) > h {
				t.Errorf("%dx%d %s: %d lines", w, h, name, len(lines))
			}
			for _, l := range lines {
				if lw := lipgloss.Width(l); lw > w {
					t.Errorf("%dx%d %s: line is %d wide: %q", w, h, name, lw, l)
					break
				}
			}
		}
		long := "example.com/" + strings.Repeat("path/", 60)

		check("home", m)
		p, _ := send(t, m, key("1"))
		check("probe form", p)
		p, _ = send(t, p, key("tab"))
		check("probe form, personas open", p)
		p, _ = send(t, p, key("esc"), key("1"))
		p, _ = send(t, p, append(typed(long), key("enter"))...)
		check("probe running", p)
		p = drain(t, p)
		check("probe results", p)

		hm, _ := send(t, m, key("2"))
		check("hunt form", hm)
		hm.hf.get("depth").sel = 1
		hm, _ = send(t, hm, append(typed(long), key("enter"))...)
		check("hunt running, deep", hm)
		hm = drain(t, hm)
		check("hunt verdict", hm)

		per, _ := send(t, m, key("4"), key("down"), key("down"))
		check("personas", per)
		har, _ := send(t, m, key("3"))
		check("har path", har)
	}
}

func TestTooSmallTerminal(t *testing.T) {
	m := sized(t, 40, 10)
	if !strings.Contains(m.View(), "needs a terminal") {
		t.Error("a tiny terminal should get a plain explanation, not a broken layout")
	}
}

func TestCtrlCQuitsFromAnywhere(t *testing.T) {
	m := sized(t, 100, 30)
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, typed("q")...) // q is text here, not quit
	if m.scr != scrHuntForm || m.hf.get("target").value() != "q" {
		t.Fatal("q inside a text field must type, not quit")
	}
	_, cmd := send(t, m, key("ctrl+c"))
	if cmd == nil {
		t.Fatal("ctrl+c should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+c should return tea.Quit")
	}
}
