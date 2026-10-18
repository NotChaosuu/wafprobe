package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// fingerprint is what a persona looks like to a fingerprinting WAF, computed
// offline from its ClientHello and HTTP/2 profile.
type fingerprint struct {
	ja4, ja3, h2 string
}

func (m model) fingerprintOf(p persona.Persona) fingerprint {
	if fp, ok := m.fps[p.ID]; ok {
		return fp
	}
	fp := fingerprint{h2: persona.AkamaiH2(p)}
	fp.ja4, _ = persona.JA4(p, "example.com")
	_, fp.ja3, _ = persona.JA3(p, "example.com")
	m.fps[p.ID] = fp
	return fp
}

func (m model) keyPersonas(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.open(scrHome)
	case "up", "k":
		if m.perIdx > 0 {
			m.perIdx--
		}
	case "down", "j":
		if m.perIdx < len(m.personas)-1 {
			m.perIdx++
		}
	}
	return m, nil
}

func personaKind(p persona.Persona) string {
	if p.Stock {
		return sWarn.Render("bare script")
	}
	return sPass.Render("browser")
}

func (m model) personasView(cw int) string {
	var b strings.Builder
	b.WriteString(sBold.Render("Who wafprobe can pretend to be") + "\n")
	b.WriteString(sDim.Render(wrap("Each persona is a full client identity: TLS ClientHello, HTTP/2 settings and ordered headers. The two bare-script personas are there on purpose, to show what an unadorned bot looks like.", cw)) + "\n\n")
	for i, p := range m.personas {
		line := padRight(p.ID, 18) + padRight(trunc(p.Name, 30), 32)
		if i == m.perIdx {
			b.WriteString(sAccent.Render("▎ ") + sHead.Render(line) + personaKind(p) + "\n")
		} else {
			b.WriteString("  " + sText.Render(line) + personaKind(p) + "\n")
		}
	}

	p := m.personas[m.perIdx]
	fp := m.fingerprintOf(p)
	inner := cw - 6
	var k strings.Builder
	row := func(label, v string) {
		k.WriteString(sDim.Render(padRight(label, 12)) + sText.Render(trunc(v, inner-12)) + "\n")
	}
	row("User-Agent", p.UserAgent)
	if fp.ja4 != "" {
		row("JA4", fp.ja4)
	} else {
		row("JA4", "set at connect time (Go's own TLS stack, not a browser profile)")
	}
	if fp.ja3 != "" {
		ja3 := fp.ja3
		if p.Randomized {
			ja3 += "  (changes every handshake; JA4 does not)"
		}
		row("JA3", ja3)
	}
	row("HTTP/2", fp.h2)
	names := make([]string, len(p.Headers))
	for i, h := range p.Headers {
		names[i] = strings.ToLower(h.Name)
	}
	row("Headers", fmt.Sprintf("%d in order: %s", len(names), strings.Join(names, ", ")))
	b.WriteString("\n" + card(strings.TrimRight(k.String(), "\n"), cw, cFaint))
	return b.String()
}
