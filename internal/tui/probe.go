package tui

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/output"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

type probeRow struct {
	p    persona.Persona
	done bool
	res  probe.Result
}

type probeEvent struct {
	gen, idx int
	res      probe.Result
}

type probeFinished struct{ gen int }

// probeOne runs a single persona through the same Runner the probe subcommand
// uses; calling it per persona is what lets rows fill in as they finish.
func probeOne(ctx context.Context, target string, p persona.Persona, repeats int) probe.Result {
	rs, err := probe.NewRunner(probe.Options{Concurrency: 1, Repeats: repeats}).RunAll(ctx, target, []persona.Persona{p})
	if err != nil || len(rs) == 0 {
		return probe.Result{Persona: p, PersonaID: p.ID, Name: p.Name, Error: fmt.Sprint(err)}
	}
	return rs[0]
}

func (m *model) newProbeForm() *form {
	ids := make([]string, len(m.personas))
	names := make([]string, len(m.personas))
	for i, p := range m.personas {
		ids[i], names[i] = p.ID, p.Name
	}
	samples := newChoice("samples", "Samples", []string{"1", "3", "5"},
		[]string{"fastest, no agreement check", "per persona, voted (default)", "per persona, voted"})
	samples.sel = 1
	return &form{fields: []*field{
		newText("target", "Target", "example.com"),
		newMulti("personas", "Personas", ids, names),
		samples,
		newButton("Run probe"),
	}}
}

func (m model) probeBudget() string {
	n := len(m.pf.get("personas").selected())
	r, _ := strconv.Atoi(m.pf.get("samples").value())
	return fmt.Sprintf("%d personas × %d samples = %d requests", n, r, n*r)
}

func (m model) keyProbeForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.open(scrHome)
		return m, nil
	}
	if m.pf.update(msg) {
		return m, m.startProbe()
	}
	return m, nil
}

func (m *model) startProbe() tea.Cmd {
	tf := m.pf.get("target")
	target, err := normalizeTarget(tf.input.Value())
	if err != nil {
		tf.err = err.Error()
		m.pf.focusID("target")
		return nil
	}
	tf.input.SetValue(target)

	pfl := m.pf.get("personas")
	var ps []persona.Persona
	for i, on := range pfl.checked {
		if on {
			ps = append(ps, m.personas[i])
		}
	}
	if len(ps) == 0 {
		pfl.err = "pick at least one persona"
		m.pf.focusID("personas")
		return nil
	}
	repeats, _ := strconv.Atoi(m.pf.get("samples").value())

	m.stopRun()
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	gen := m.gen
	ch := make(chan tea.Msg, len(ps)+1)
	m.events = ch
	m.probeTarget = target
	m.probeRows = make([]probeRow, len(ps))
	for i, p := range ps {
		m.probeRows[i].p = p
	}
	run := m.probeFn
	go func() {
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for i, p := range ps {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, p persona.Persona) {
				defer wg.Done()
				defer func() { <-sem }()
				ch <- probeEvent{gen: gen, idx: i, res: run(ctx, target, p, repeats)}
			}(i, p)
		}
		wg.Wait()
		ch <- probeFinished{gen: gen}
	}()
	m.started = time.Now()
	m.scr = scrProbeRun
	return tea.Batch(waitFor(ch), m.spin.Tick)
}

func (m model) probeResults() []probe.Result {
	out := make([]probe.Result, 0, len(m.probeRows))
	for _, r := range m.probeRows {
		if r.done {
			out = append(out, r.res)
		}
	}
	return out
}

func (m model) keyProbeResult(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.open(scrProbeForm)
		return m, nil
	case "r":
		return m, m.startProbe()
	case "e":
		rs := m.probeResults()
		m.export("probe", m.probeTarget, func(w io.Writer) error {
			return output.JSON(w, m.probeTarget, rs, m.version)
		})
		return m, nil
	case "h":
		// Carry the target over, starting from a persona that was blocked: that
		// is the case where a hunt has something to find.
		m.capture = nil
		m.hf.get("target").input.SetValue(m.probeTarget)
		if id := m.firstBlocked(); id != "" {
			pf := m.hf.get("persona")
			for i, o := range pf.options {
				if o == id {
					pf.sel = i
				}
			}
		}
		m.open(scrHuntForm)
		m.hf.focusID("persona")
		return m, nil
	}
	return m.scrollKey(msg)
}

func (m model) firstBlocked() string {
	for _, r := range m.probeRows {
		if r.done && r.res.Error == "" && r.res.Detection.Blocked {
			return r.p.ID
		}
	}
	return ""
}

const probeHeader = "    PERSONA           CODE   VENDOR            LAYER       SIGNAL"

func probeLine(r probeRow, spin string, cw int) string {
	if !r.done {
		return spin + "   " + sDim.Render(padRight(r.p.ID, 18)+"probing…")
	}
	res := r.res
	icon, layerSt := sPass.Render("✓"), sPass
	switch {
	case res.Error != "":
		icon, layerSt = sWarn.Render("!"), sWarn
	case res.Detection.Blocked:
		icon, layerSt = sBlock.Render("✗"), sBlock
	}
	code := "ERR"
	if res.Error == "" {
		code = strconv.Itoa(res.Status)
	}
	vendor := res.Detection.Vendor
	if vendor == "" {
		vendor = "–"
	}
	if n := len(res.Detection.Also); n > 0 {
		vendor = fmt.Sprintf("%s +%d", vendor, n)
	}
	layer := string(res.Detection.Layer)
	if layer == "" {
		layer = "–"
	}
	detail := signal(res)
	if res.Error != "" {
		detail = res.Error
	}
	flake := ""
	if res.Samples > 1 && res.Agree < res.Samples {
		flake = fmt.Sprintf("  %d/%d agreed", res.Agree, res.Samples)
	}
	room := cw - 60 - len(flake)
	if room < 10 {
		room = 10
	}
	return icon + "   " + sText.Render(padRight(res.PersonaID, 18)) +
		sText.Render(padRight(code, 7)) +
		sText.Render(padRight(trunc(vendor, 16), 18)) +
		layerSt.Render(padRight(layer, 12)) +
		sDim.Render(trunc(detail, room)) + sWarn.Render(flake)
}

// signal picks the most telling match for the row: a body or cookie marker
// says which mechanism fired, where a header usually only repeats the vendor.
func signal(r probe.Result) string {
	sigs := r.Detection.Signals
	if len(sigs) == 0 {
		if r.Detection.Layer == detect.LayerPass {
			return "clean"
		}
		return "–"
	}
	for _, prefix := range []string{"body:", "transport:", "cookie:"} {
		for _, s := range sigs {
			if strings.HasPrefix(strings.ToLower(s), prefix) {
				return s
			}
		}
	}
	return sigs[0]
}

func (m model) probeRunView(cw int) string {
	done := 0
	for _, r := range m.probeRows {
		if r.done {
			done++
		}
	}
	var b strings.Builder
	b.WriteString(sBold.Render(trunc(m.probeTarget, cw-10)) + "\n")
	b.WriteString(bar(done, len(m.probeRows), 32) + "  " +
		sText.Render(fmt.Sprintf("%d/%d", done, len(m.probeRows))) + "  " +
		sDim.Render(clock(time.Since(m.started))) + "\n\n")
	b.WriteString(sDim.Render(probeHeader) + "\n")
	for _, r := range m.probeRows {
		b.WriteString(probeLine(r, m.spin.View(), cw) + "\n")
	}
	return b.String()
}

func (m model) probeResultView(cw int) string {
	rs := m.probeResults()
	s := probe.Summarize(m.probeTarget, rs)
	var b strings.Builder
	b.WriteString(sBold.Render(trunc(m.probeTarget, cw-10)) + "\n\n")

	chips := []string{pill(fmt.Sprintf("%d passed", s.Passed), cPass)}
	if s.Blocked > 0 {
		chips = append(chips, pill(fmt.Sprintf("%d blocked", s.Blocked), cBlock))
	}
	if s.Errored > 0 {
		chips = append(chips, pill(fmt.Sprintf("%d errored", s.Errored), cWarn))
	}
	b.WriteString(strings.Join(chips, " ") + "  " +
		sDim.Render(fmt.Sprintf("%d personas · %.1fs", s.TotalPersonas, m.elapsed.Seconds())) + "\n")
	if len(s.DetectedVendors) > 0 {
		v := append([]string(nil), s.DetectedVendors...)
		sort.Strings(v)
		b.WriteString(sDim.Render("in front of it: ") + sText.Render(strings.Join(v, ", ")) + "\n")
	}
	b.WriteString("\n" + sDim.Render(probeHeader) + "\n")
	for _, r := range m.probeRows {
		b.WriteString(probeLine(r, " ", cw) + "\n")
	}
	b.WriteString("\n")

	switch {
	case s.Flaky > 0:
		b.WriteString(sWarn.Render(wrap(fmt.Sprintf("%d persona(s) got different answers across samples. The target is rate-limiting or scoring this IP; re-run before trusting a row marked “agreed”.", s.Flaky), cw)) + "\n\n")
	}
	switch {
	case s.Blocked > 0 && s.Passed > 0:
		b.WriteString(card(sText.Render("Some clients pass and some don't, so the target is telling them apart.")+"\n"+
			sDim.Render("Press ")+sHead.Render("h")+sDim.Render(" to hunt from "+m.firstBlocked()+" and find the signal that got it blocked."), cw, cAccent))
	case s.Blocked > 0:
		b.WriteString(card(sText.Render("Every client that answered was blocked.")+"\n"+
			sDim.Render("Press ")+sHead.Render("h")+sDim.Render(" to hunt for a single change that gets through. If none does, it is likely a JS challenge or an IP-level block."), cw, cBlock))
	case s.Passed > 0:
		b.WriteString(card(sText.Render("Nothing was blocked on this URL.")+"\n"+
			sDim.Render("Bot managers often guard only login, cart and API routes. Try one of those, or press ")+sHead.Render("h")+sDim.Render(" to see which changes this page is sensitive to."), cw, cFaint))
	}
	return b.String()
}
