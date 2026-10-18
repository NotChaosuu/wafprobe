package tui

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NotChaosuu/wafprobe/internal/hunt"
	"github.com/NotChaosuu/wafprobe/internal/output"
	"github.com/NotChaosuu/wafprobe/internal/persona"
)

type huntCell struct {
	name, axis string
	done       bool
	res        hunt.MutationResult
}

// huntRun is what the current (or last) hunt was started with.
type huntRun struct {
	target  string
	persona string
	repeats int
	deep    bool
}

type huntEvent struct {
	gen int
	res hunt.MutationResult
}

type huntFinished struct {
	gen int
	rep *hunt.Report
	err error
}

var bodyMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

func (m *model) newHuntForm() *form {
	ids := make([]string, len(m.personas))
	names := make([]string, len(m.personas))
	def := 0
	for i, p := range m.personas {
		ids[i], names[i] = p.ID, p.Name
		if p.ID == "chrome-latest" {
			def = i
		}
	}
	pf := newChoice("persona", "Start from", ids, names)
	pf.sel = def
	depth := newChoice("depth", "Depth", []string{"standard", "deep"}, []string{
		fmt.Sprintf("%d probes, one per common signal", len(hunt.AllMutations())),
		fmt.Sprintf("%d probes, adds client hints, fetch metadata, more UAs and methods", len(hunt.DeepMutations())),
	})
	method := newChoice("method", "Method", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}, nil)
	body := newText("body", "Body", `{"user":"x"}  (sent on every probe)`)
	body.hidden = func() bool { return !bodyMethods[method.value()] }
	samples := newChoice("samples", "Samples", []string{"3", "5", "7"},
		[]string{"per probe, voted (default)", "per probe, steadier on a noisy target", "per probe, slowest and steadiest"})
	return &form{fields: []*field{
		newText("target", "Target", "example.com/login"),
		pf, depth, method, body, samples,
		newButton("Run hunt"),
	}}
}

func (m model) huntMutations() []hunt.Mutation {
	if m.hf.get("depth").value() == "deep" {
		return hunt.DeepMutations()
	}
	return hunt.AllMutations()
}

func (m model) huntBudget() string {
	n := len(m.huntMutations())
	r, _ := strconv.Atoi(m.hf.get("samples").value())
	s := fmt.Sprintf("%d probes × %d samples + 6 baseline = about %d requests", n, r, n*r+6)
	if c := m.capture; c != nil {
		s += "\n" + strings.Repeat(" ", 2+labelW) + "replaying capture: " + trunc(c.Name, 50) +
			fmt.Sprintf(" (%d headers", len(c.Headers))
		if c.Cookie != "" {
			s += ", cookies"
		}
		s += ")"
	}
	return s
}

func (m model) keyHuntForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.open(scrHome)
		return m, nil
	}
	if m.hf.update(msg) {
		return m, m.startHunt()
	}
	return m, nil
}

func (m *model) startHunt() tea.Cmd {
	tf := m.hf.get("target")
	target, err := normalizeTarget(tf.input.Value())
	if err != nil {
		tf.err = err.Error()
		m.hf.focusID("target")
		return nil
	}
	tf.input.SetValue(target)

	p, _ := persona.ByID(m.hf.get("persona").value())
	method := m.hf.get("method").value()
	repeats, _ := strconv.Atoi(m.hf.get("samples").value())
	muts := m.huntMutations()

	var body []byte
	if bodyMethods[method] {
		body = []byte(m.hf.get("body").input.Value())
	}
	var headers []persona.HeaderField
	cookie := ""
	// A capture replays the browser's own request shape on top of the chosen
	// TLS persona, the same way `hunt --persona-file` does.
	if c := m.capture; c != nil {
		if c.UserAgent != "" {
			p.UserAgent = c.UserAgent
		}
		if len(body) == 0 {
			body, _ = c.Body()
		}
		cookie, headers = c.Cookie, c.Headers
	}

	m.stopRun()
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	gen := m.gen
	ch := make(chan tea.Msg, len(muts)+2)
	m.events = ch

	m.huntRun = huntRun{target: target, persona: p.ID, repeats: repeats, deep: len(muts) > len(hunt.AllMutations())}
	m.cells = make([]huntCell, len(muts))
	for i, mu := range muts {
		m.cells[i] = huntCell{name: mu.Name, axis: mu.Axis}
	}
	m.nDone, m.recent, m.rep = 0, nil, nil

	run := m.huntFn
	opts := hunt.Options{
		Persona: p, Mutations: muts, Method: method, Body: body,
		ExtraHeaders: headers, Cookie: cookie, Repeats: repeats,
		Logger: func(_, _ int, res hunt.MutationResult) { ch <- huntEvent{gen: gen, res: res} },
	}
	go func() {
		rep, err := run(ctx, target, opts)
		ch <- huntFinished{gen: gen, rep: rep, err: err}
	}()
	m.started = time.Now()
	m.scr = scrHuntRun
	return tea.Batch(waitFor(ch), m.spin.Tick)
}

func (m *model) recordHunt(res hunt.MutationResult) {
	for i := range m.cells {
		if !m.cells[i].done && m.cells[i].name == res.Mutation.Name {
			m.cells[i].done, m.cells[i].res = true, res
			break
		}
	}
	m.nDone++
	m.recent = append(m.recent, res)
	if len(m.recent) > 5 {
		m.recent = m.recent[len(m.recent)-5:]
	}
}

func (m model) deepToggleLabel() string {
	if m.huntRun.deep {
		return "re-run standard"
	}
	return "re-run deep"
}

func (m model) keyHuntResult(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.open(scrHuntForm)
		return m, nil
	case "r":
		return m, m.startHunt()
	case "d":
		d := m.hf.get("depth")
		d.sel = 1 - d.sel
		return m, m.startHunt()
	case "c":
		if _, curl, ok := bypass(m.rep); ok {
			if err := m.copyFn(curl); err != nil {
				m.say(false, "could not reach the clipboard (%v) — select the command with the mouse instead", err)
			} else {
				m.say(true, "curl command copied to the clipboard")
			}
		}
		return m, nil
	case "e":
		if m.rep != nil {
			rep := m.rep
			m.export("hunt", rep.Target, func(w io.Writer) error { return output.HuntJSON(w, rep, m.version) })
		}
		return m, nil
	}
	return m.scrollKey(msg)
}

func outcomeDot(done bool, o hunt.Outcome) string {
	if !done {
		return sFaint.Render("○")
	}
	switch o {
	case hunt.OutcomePass:
		return sPass.Render("●")
	case hunt.OutcomeBlocked:
		return sBlock.Render("●")
	case hunt.OutcomeError:
		return sWarn.Render("▲")
	default:
		return sDim.Render("–")
	}
}

func outcomeWord(o hunt.Outcome) string {
	switch o {
	case hunt.OutcomePass:
		return sPass.Render("pass ")
	case hunt.OutcomeBlocked:
		return sBlock.Render("block")
	case hunt.OutcomeError:
		return sWarn.Render("error")
	case hunt.OutcomeNA:
		return sDim.Render("n/a  ")
	}
	return sDim.Render("?    ")
}

func legend() string {
	return sPass.Render("●") + sDim.Render(" pass   ") + sBlock.Render("●") + sDim.Render(" block   ") +
		sWarn.Render("▲") + sDim.Render(" error   – could not be tested   ") + sFaint.Render("○") + sDim.Render(" waiting")
}

// axes returns the axis names in the order the matrix introduces them.
func axes(cells []huntCell) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cells {
		if !seen[c.axis] {
			seen[c.axis] = true
			out = append(out, c.axis)
		}
	}
	return out
}

func (m model) huntRunView(cw int) string {
	total := len(m.cells)
	phase := "probing, one change at a time"
	switch {
	case m.nDone == 0:
		phase = "sampling the baseline"
	case m.nDone >= total:
		phase = "re-checking the baseline to measure noise"
	}
	var b strings.Builder
	b.WriteString(sBold.Render(trunc(m.huntRun.target, cw-10)) + "\n")
	b.WriteString(sDim.Render(fmt.Sprintf("from %s · %d probes × %d samples", m.huntRun.persona, total, m.huntRun.repeats)) + "\n\n")
	b.WriteString(m.spin.View() + " " + sText.Render(phase) + "\n")
	b.WriteString(bar(m.nDone, total, 32) + "  " + sText.Render(fmt.Sprintf("%d/%d", m.nDone, total)) + "  " +
		sDim.Render(clock(time.Since(m.started))) + "\n\n")

	for _, ax := range axes(m.cells) {
		row := sDim.Render(padRight(ax, 16))
		n := 0
		for _, c := range m.cells {
			if c.axis != ax {
				continue
			}
			// Deep mode has long axes; wrap the dots under the label column.
			if n > 0 && n%30 == 0 {
				row += "\n" + strings.Repeat(" ", 16)
			}
			row += outcomeDot(c.done, c.res.Outcome) + " "
			n++
		}
		b.WriteString(row + "\n")
	}
	b.WriteString("\n" + legend() + "\n")

	// Only show the tail when there is room; the dots are the main display.
	if used := lipgloss.Height(b.String()); len(m.recent) > 0 && used+len(m.recent)+1 < m.bodyH() {
		b.WriteString("\n")
		for _, r := range m.recent {
			b.WriteString(outcomeWord(r.Outcome) + "  " + sText.Render(trunc(r.Mutation.Name, cw-10)) + "\n")
		}
	}
	return b.String()
}

func chips(items []string, bg lipgloss.TerminalColor) string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = pill(it, bg)
	}
	return strings.Join(out, " ")
}

func (m model) huntResultView(cw int) string {
	r := m.rep
	if r == nil {
		return ""
	}
	f := r.Findings
	inner := cw - 6
	var b strings.Builder
	b.WriteString(sBold.Render(trunc(r.Target, cw-10)) + "\n")
	b.WriteString(sDim.Render(fmt.Sprintf("from %s · %d probes · sampled %d× · %.1fs",
		r.Persona.ID, len(r.Results), r.Repeats, m.elapsed.Seconds())) + "\n\n")

	baseline := sPass.Render("passed")
	if r.BaselineOutcome == hunt.OutcomeBlocked {
		baseline = sBlock.Render("blocked")
	}
	if r.BaselineDetection.Vendor != "" {
		if r.BaselineOutcome == hunt.OutcomeBlocked {
			baseline += sDim.Render(" by ") + sText.Render(r.BaselineDetection.Vendor)
		} else {
			baseline += sDim.Render(" · ") + sText.Render(r.BaselineDetection.Vendor) + sDim.Render(" in front")
		}
	}
	if r.BaselineStatus != 0 {
		baseline += sDim.Render(fmt.Sprintf(" (HTTP %d)", r.BaselineStatus))
	}

	switch {
	case !r.Reachable:
		b.WriteString(card(sBlock.Bold(true).Render("Could not reach the target")+"\n"+
			sText.Render(wrap(f.Summary, inner)), cw, cBlock))
	case f.Unstable:
		b.WriteString(card(sWarn.Bold(true).Render("Run unstable — no signal can be named")+"\n"+
			sDim.Render("baseline ")+baseline+"\n\n"+
			sText.Render(wrap(f.Summary, inner)), cw, cWarn))
	default:
		var c strings.Builder
		c.WriteString(sDim.Render("baseline  ") + baseline + "\n\n")
		row := func(label, body string) { c.WriteString(sDim.Render(padRight(label, 10)) + body + "\n") }
		if len(f.Checks) > 0 {
			row("checks", chips(f.Checks, cAccent))
		} else {
			row("checks", sDim.Render("nothing that was tested"))
		}
		if len(f.Ignores) > 0 {
			row("ignores", sText.Render(wrap(strings.Join(f.Ignores, " · "), inner-10)))
		}
		if len(f.Untested) > 0 {
			row("untested", sWarn.Render(strings.Join(f.Untested, " · "))+sDim.Render("  could not be confirmed on the wire"))
		}
		c.WriteString("\n" + sText.Render(wrap(verdictSentence(r), inner)))
		border := lipgloss.TerminalColor(cAccent)
		if len(f.Checks) == 0 {
			border = cFaint
		}
		b.WriteString(card(c.String(), cw, border))
	}
	b.WriteString("\n\n")

	if name, curl, ok := bypass(r); ok {
		b.WriteString(sHead.Render("Gets through") + sDim.Render("  "+name+"  ·  press ") + sHead.Render("c") + sDim.Render(" to copy") + "\n")
		b.WriteString(card(sText.Render(curl), cw, cPass) + "\n\n")
	}
	if r.Reachable {
		b.WriteString(m.huntMatrix(r, cw))
	}
	return b.String()
}

// bypass returns a ready-to-run request for the first change that got through.
// Same gate as the CLI: only when the baseline was blocked and the run was
// stable enough to believe the probe that passed.
func bypass(r *hunt.Report) (name, curl string, ok bool) {
	if r == nil || !r.Reachable || r.Findings.Unstable || r.BaselineOutcome != hunt.OutcomeBlocked {
		return "", "", false
	}
	for _, res := range r.Results {
		if res.Outcome == hunt.OutcomePass {
			return res.Mutation.Name, hunt.CurlFor(r.Target, r.Method, r.Persona.UserAgent, r.Cookie, r.Body, r.Headers, res.Mutation), true
		}
	}
	return "", "", false
}

func verdictSentence(r *hunt.Report) string {
	f := r.Findings
	who := r.Persona.ID
	var s string
	switch blocked := r.BaselineOutcome == hunt.OutcomeBlocked; {
	case blocked && len(f.Checks) > 0:
		s = fmt.Sprintf("%s is blocked as-is, and changing %s got it through. That is what this target is keying on.", who, strings.Join(f.Checks, " or "))
	case blocked && len(f.PassingMutations) > 0:
		s = fmt.Sprintf("%s is blocked as-is. A few changes got through, but not consistently enough to name a signal.", who)
	case blocked:
		s = fmt.Sprintf("%s is blocked and no single change got it through. That usually means a JavaScript challenge or an IP-level block, not a fingerprint rule.", who)
	case len(f.Checks) > 0:
		s = fmt.Sprintf("%s passes as-is, but changing %s gets it blocked. The target is watching those.", who, strings.Join(f.Checks, " or "))
	default:
		s = fmt.Sprintf("%s passes as-is and none of the tested changes made a difference.", who)
	}
	if r.NoiseFloor > 0 {
		s += fmt.Sprintf(" The target answered at least one probe inconsistently (noise floor %.0f%%), so treat a borderline signal with care.", r.NoiseFloor*100)
	}
	return s
}

func (m model) huntMatrix(r *hunt.Report, cw int) string {
	nameW := cw - 46
	if nameW < 20 {
		nameW = 20
	}
	if nameW > 40 {
		nameW = 40
	}
	var b strings.Builder
	b.WriteString(sDim.Render("    "+padRight("CHANGE", nameW)+padRight("SIGNAL", 14)+padRight("RESULT", 8)+padRight("AGREED", 9)+"CODE") + "\n")
	flips := 0
	for _, res := range r.Results {
		flipped := (res.Outcome == hunt.OutcomePass || res.Outcome == hunt.OutcomeBlocked) && res.Outcome != r.BaselineOutcome
		mark, nameSt := "  ", sText
		if flipped {
			mark, nameSt = sAccent.Render("◆ "), sBold
			flips++
		}
		agreed := sDim.Render(padRight(fmt.Sprintf("%d/%d", res.Agree, res.Samples), 9))
		if res.Samples > 0 && res.Agree < res.Samples {
			agreed = sWarn.Render(padRight(fmt.Sprintf("%d/%d", res.Agree, res.Samples), 9))
		}
		tail := sDim.Render(strconv.Itoa(res.Status))
		switch {
		case res.Outcome == hunt.OutcomeError:
			tail = sWarn.Render(trunc(res.Error, cw-nameW-38))
		case res.Outcome == hunt.OutcomeNA:
			tail = sDim.Render("change didn't reach the wire")
		case res.Status == 0:
			tail = ""
		}
		b.WriteString(mark + outcomeDot(true, res.Outcome) + " " +
			nameSt.Render(padRight(trunc(res.Mutation.Name, nameW-1), nameW)) +
			sDim.Render(padRight(res.Mutation.Axis, 14)) +
			outcomeWord(res.Outcome) + "   " + agreed + tail + "\n")
	}
	if flips > 0 {
		b.WriteString("\n" + sAccent.Render("◆") + sDim.Render(" answered differently from the baseline") + "\n")
	}
	return b.String()
}
