package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/NotChaosuu/wafprobe/internal/harimport"
)

// harMatches returns the indices of entries whose URL contains the filter.
func (m model) harMatches() []int {
	if m.har == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(m.harFilter.Value()))
	var out []int
	for i, e := range m.har.Log.Entries {
		if q == "" || strings.Contains(strings.ToLower(e.Request.URL), q) {
			out = append(out, i)
		}
	}
	return out
}

func (m model) keyHAR(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch m.scr {
	case scrHARPath:
		if key == "esc" {
			m.open(scrHome)
			return m, nil
		}
		if !m.harf.update(msg) {
			return m, nil
		}
		pf := m.harf.get("path")
		// Dragging a file into a terminal pastes it quoted.
		path := strings.Trim(pf.input.Value(), "\"' ")
		if path == "" {
			pf.err = "enter the path to a .har file"
			return m, nil
		}
		h, err := harimport.Parse(path)
		if err != nil {
			pf.err = err.Error()
			return m, nil
		}
		if len(h.Log.Entries) == 0 {
			pf.err = "that HAR has no requests in it"
			return m, nil
		}
		m.har, m.harPath, m.harIdx = h, path, 0
		m.harFilter.SetValue("")
		m.harFilter.Focus()
		m.scr = scrHARPick

	case scrHARPick:
		matches := m.harMatches()
		switch key {
		case "esc":
			m.open(scrHARPath)
		case "up":
			if m.harIdx > 0 {
				m.harIdx--
			}
		case "down":
			if m.harIdx < len(matches)-1 {
				m.harIdx++
			}
		case "enter":
			if len(matches) > 0 {
				m.captureEntry(matches[m.harIdx])
			}
		default:
			m.harFilter, _ = m.harFilter.Update(msg)
			m.harIdx = 0
		}

	case scrHARDone:
		switch key {
		case "esc":
			m.open(scrHome)
		case "h":
			c := m.harCap
			m.capture = c
			m.hf.get("target").input.SetValue(c.URL)
			mf := m.hf.get("method")
			for i, o := range mf.options {
				if strings.EqualFold(o, c.Method) {
					mf.sel = i
				}
			}
			m.open(scrHuntForm)
		}
	}
	return m, nil
}

func (m *model) captureEntry(i int) {
	e := &m.har.Log.Entries[i]
	id := capturedID(e.Request.URL)
	c := e.ToCaptured(id, id)
	stem := strings.TrimSuffix(filepath.Base(m.harPath), filepath.Ext(m.harPath))
	out := filepath.Join(filepath.Dir(m.harPath), stem+"-captured.json")
	if err := harimport.SaveCaptured(out, c); err != nil {
		m.say(false, "could not save the capture: %v", err)
		return
	}
	m.harCap, m.harOut = c, out
	m.scr = scrHARDone
}

// capturedID mirrors the slug `wafprobe import-har` gives a capture.
func capturedID(rawURL string) string {
	id := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	id = strings.Trim(strings.NewReplacer("/", "-", "?", "-", "&", "-", "=", "-").Replace(id), "-")
	if len(id) > 60 {
		id = id[:60]
	}
	return "captured:" + id
}

func (m model) harView(cw int) string {
	var b strings.Builder
	switch m.scr {
	case scrHARPath:
		b.WriteString(sBold.Render("Replay a real browser request") + "\n")
		b.WriteString(sDim.Render(wrap("In DevTools → Network, reproduce the action (a login, a checkout), right-click any request and choose “Save all as HAR with content”. wafprobe lifts the exact headers, cookies and body from the request you pick, so a hunt can start from a shape the WAF already accepted.", cw)) + "\n\n")
		b.WriteString(m.harf.view(cw))

	case scrHARPick:
		matches := m.harMatches()
		b.WriteString(sBold.Render("Which request?") + "  " +
			sDim.Render(fmt.Sprintf("%d of %d in %s", len(matches), len(m.har.Log.Entries), trunc(filepath.Base(m.harPath), 40))) + "\n")
		b.WriteString(sAccent.Render("/ ") + m.harFilter.View() + "\n\n")
		if len(matches) == 0 {
			b.WriteString(sDim.Render("no request URL contains that text"))
			break
		}
		rows := m.bodyH() - 4
		start := m.harIdx - rows/2
		if start > len(matches)-rows {
			start = len(matches) - rows
		}
		if start < 0 {
			start = 0
		}
		for n := start; n < len(matches) && n < start+rows; n++ {
			req := m.har.Log.Entries[matches[n]].Request
			line := padRight(req.Method, 8) + trunc(req.URL, cw-12)
			if n == m.harIdx {
				b.WriteString(sAccent.Render("❯ ") + sBold.Render(line) + "\n")
			} else {
				b.WriteString("  " + sText.Render(line) + "\n")
			}
		}

	case scrHARDone:
		c := m.harCap
		b.WriteString(sBold.Render("Capture saved") + "\n\n")
		var k strings.Builder
		row := func(label, v string) { k.WriteString(sDim.Render(padRight(label, 10)) + sText.Render(v) + "\n") }
		row("request", c.Method+" "+trunc(c.URL, cw-24))
		row("contains", c.Summarize())
		row("file", m.harOut)
		k.WriteString("\n" + sWarn.Render(wrap("This file holds the session cookies and any Authorization header from that request. Treat it like a password and keep it out of git.", cw-6)))
		b.WriteString(card(k.String(), cw, cPass) + "\n\n")
		b.WriteString(sDim.Render("Press ") + sHead.Render("h") + sDim.Render(" to hunt with it now, or later: ") +
			sText.Render("wafprobe hunt --persona-file <file> <url>"))
	}
	return b.String()
}
