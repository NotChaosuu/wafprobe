package tui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// uaGate is a target that blocks everything except a Googlebot User-Agent, with
// a Cloudflare-shaped challenge so the detectors have something to name.
func uaGate(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.UserAgent(), "Googlebot") {
			w.Write([]byte("ok"))
			return
		}
		w.Header().Set("CF-Ray", "fake-ray")
		w.Header().Set("CF-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<title>Just a moment...</title>"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// real engines, nothing faked between keypress and socket
func TestEndToEndHunt(t *testing.T) {
	srv := uaGate(t)
	m := sized(t, 110, 40)
	m, _ = send(t, m, key("2"))
	m, _ = send(t, m, append(typed(srv.URL), key("enter"))...)
	if m.scr != scrHuntRun {
		t.Fatalf("hunt did not start: screen %d, %s", m.scr, m.hf.get("target").err)
	}
	for m.running() {
		select {
		case msg := <-m.events:
			m, _ = send(t, m, msg)
		case <-time.After(60 * time.Second):
			t.Fatal("hunt never finished")
		}
	}
	if m.scr != scrHuntResult || m.rep == nil {
		t.Fatalf("no verdict: screen %d flash %q", m.scr, m.flash)
	}
	if got := m.rep.Findings.Checks; len(got) != 1 || got[0] != "user-agent" {
		t.Errorf("Checks = %v, want [user-agent]", got)
	}
	if m.nDone != len(m.cells) {
		t.Errorf("live matrix saw %d of %d probes", m.nDone, len(m.cells))
	}
	for _, c := range m.cells {
		if !c.done {
			t.Errorf("probe %q never reported to the live view", c.name)
		}
	}
	content := m.huntResultView(m.contentW())
	for _, want := range []string{"cloudflare", "user-agent", "Gets through", "Googlebot"} {
		if !strings.Contains(content, want) {
			t.Errorf("verdict is missing %q", want)
		}
	}
}

func TestEndToEndProbe(t *testing.T) {
	srv := uaGate(t)
	m := sized(t, 110, 40)
	m, _ = send(t, m, key("1"))
	m, _ = send(t, m, append(typed(srv.URL), key("enter"))...)
	for m.running() {
		select {
		case msg := <-m.events:
			m, _ = send(t, m, msg)
		case <-time.After(60 * time.Second):
			t.Fatal("probe never finished")
		}
	}
	if m.scr != scrProbeResult {
		t.Fatalf("no results: screen %d", m.scr)
	}
	blocked := 0
	for _, r := range m.probeRows {
		if !r.done {
			t.Errorf("%s never finished", r.p.ID)
		}
		if r.res.Detection.Blocked {
			blocked++
		}
	}
	if blocked != len(m.probeRows) {
		t.Errorf("every persona should be blocked by the UA gate, got %d of %d", blocked, len(m.probeRows))
	}
	if v := m.View(); !strings.Contains(v, "blocked") || !strings.Contains(v, "cloudflare") {
		t.Error("results screen does not show the block")
	}
}

// The real Bubble Tea program starts, draws, takes a key and exits cleanly
// without a terminal attached.
func TestProgramStartsAndQuits(t *testing.T) {
	var out bytes.Buffer
	p := tea.NewProgram(newModel("test"), tea.WithInput(strings.NewReader("")), tea.WithOutput(&out))
	done := make(chan error, 1)
	go func() {
		_, err := p.Run()
		done <- err
	}()
	p.Send(tea.WindowSizeMsg{Width: 100, Height: 30})
	p.Send(key("down"))
	p.Send(key("q"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("program exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		p.Kill()
		t.Fatal("program did not quit on q")
	}
	if !strings.Contains(out.String(), "wafprobe") {
		t.Error("program drew nothing")
	}
}
