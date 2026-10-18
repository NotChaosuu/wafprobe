// Package tui is the interactive UI shown when wafprobe runs with no arguments.
// It uses the same engines as the subcommands.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/harimport"
	"github.com/NotChaosuu/wafprobe/internal/hunt"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

type screen int

const (
	scrHome screen = iota
	scrProbeForm
	scrProbeRun
	scrProbeResult
	scrHuntForm
	scrHuntRun
	scrHuntResult
	scrHARPath
	scrHARPick
	scrHARDone
	scrPersonas
)

// Smallest terminal the layout is designed for.
const (
	minW = 64
	minH = 18
)

type menuItem struct {
	title, desc string
	scr         screen
	quit        bool
}

var menu = []menuItem{
	{title: "Probe", desc: "Send every client persona at a URL and see who gets blocked", scr: scrProbeForm},
	{title: "Hunt", desc: "Change one thing per request to find what the WAF keys on", scr: scrHuntForm},
	{title: "Import HAR", desc: "Turn a DevTools capture into a replayable browser persona", scr: scrHARPath},
	{title: "Personas", desc: "Browse the built-in clients and their fingerprints", scr: scrPersonas},
	{title: "Quit", quit: true},
}

type model struct {
	version string
	w, h    int
	scr     screen
	homeIdx int
	flash   string
	flashOK bool

	spin spinner.Model
	vp   viewport.Model

	// One run at a time. gen invalidates events from a cancelled run.
	gen     int
	cancel  context.CancelFunc
	events  chan tea.Msg
	started time.Time
	elapsed time.Duration

	personas []persona.Persona

	pf          *form
	probeTarget string
	probeRows   []probeRow
	probeFn     func(ctx context.Context, target string, p persona.Persona, repeats int) probe.Result

	hf      *form
	capture *harimport.Captured
	cells   []huntCell
	nDone   int
	recent  []hunt.MutationResult
	huntRun huntRun
	rep     *hunt.Report
	huntFn  func(ctx context.Context, target string, opts hunt.Options) (*hunt.Report, error)
	copyFn  func(string) error

	harf      *form
	har       *harimport.HAR
	harPath   string
	harFilter textinput.Model
	harIdx    int
	harOut    string
	harCap    *harimport.Captured

	perIdx int
	fps    map[string]fingerprint
}

// Run starts the interactive UI and blocks until the user quits.
func Run(version string) error {
	_, err := tea.NewProgram(newModel(version), tea.WithAltScreen()).Run()
	return err
}

func newModel(version string) model {
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	sp.Style = sAccent
	m := model{
		version:  version,
		spin:     sp,
		vp:       viewport.New(80, 20),
		personas: persona.All(),
		fps:      map[string]fingerprint{},
		probeFn:  probeOne,
		huntFn:   hunt.Run,
		copyFn:   clipboard.WriteAll,
	}
	m.pf = m.newProbeForm()
	m.hf = m.newHuntForm()
	m.harf = &form{fields: []*field{
		newText("path", "HAR file", `C:\path\to\devtools.har  (drag the file in)`),
		newButton("Open"),
	}}
	m.harFilter = newText("filter", "", "type to filter by URL").input
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) contentW() int {
	w := m.w - 4
	if w > 104 {
		w = 104
	}
	if w < minW-4 {
		w = minW - 4
	}
	return w
}

func (m model) bodyH() int { return m.h - 4 }

func (m model) running() bool { return m.scr == scrProbeRun || m.scr == scrHuntRun }

func (m *model) layout() {
	m.vp.Width = m.contentW()
	m.vp.Height = m.bodyH()
	switch m.scr {
	case scrProbeResult:
		m.vp.SetContent(m.probeResultView(m.contentW()))
	case scrHuntResult:
		m.vp.SetContent(m.huntResultView(m.contentW()))
	}
}

func (m *model) say(ok bool, format string, a ...any) {
	m.flash, m.flashOK = fmt.Sprintf(format, a...), ok
}

func (m *model) stopRun() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.gen++
}

func waitFor(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *model) open(s screen) {
	m.scr = s
	switch s {
	case scrProbeForm:
		m.pf.setFocus(0)
	case scrHuntForm:
		m.hf.setFocus(0)
	case scrHARPath:
		m.harf.setFocus(0)
	case scrProbeResult, scrHuntResult:
		m.layout()
		m.vp.GotoTop()
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()
		return m, nil

	case spinner.TickMsg:
		if !m.running() {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case probeEvent:
		if msg.gen != m.gen {
			return m, nil
		}
		m.probeRows[msg.idx].done = true
		m.probeRows[msg.idx].res = msg.res
		return m, waitFor(m.events)

	case probeFinished:
		if msg.gen != m.gen {
			return m, nil
		}
		m.elapsed = time.Since(m.started)
		m.cancel = nil
		m.open(scrProbeResult)
		return m, nil

	case huntEvent:
		if msg.gen != m.gen {
			return m, nil
		}
		m.recordHunt(msg.res)
		return m, waitFor(m.events)

	case huntFinished:
		if msg.gen != m.gen {
			return m, nil
		}
		m.elapsed = time.Since(m.started)
		m.cancel = nil
		if msg.err != nil {
			m.open(scrHuntForm)
			m.say(false, "hunt failed: %v", msg.err)
			return m, nil
		}
		m.rep = msg.rep
		m.open(scrHuntResult)
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.stopRun()
			return m, tea.Quit
		}
		m.flash = ""
		switch m.scr {
		case scrHome:
			return m.keyHome(msg)
		case scrProbeForm:
			return m.keyProbeForm(msg)
		case scrHuntForm:
			return m.keyHuntForm(msg)
		case scrProbeRun, scrHuntRun:
			if msg.String() == "esc" {
				m.stopRun()
				if m.scr == scrProbeRun {
					m.open(scrProbeForm)
				} else {
					m.open(scrHuntForm)
				}
				m.say(false, "run cancelled")
			}
			return m, nil
		case scrProbeResult:
			return m.keyProbeResult(msg)
		case scrHuntResult:
			return m.keyHuntResult(msg)
		case scrHARPath, scrHARPick, scrHARDone:
			return m.keyHAR(msg)
		case scrPersonas:
			return m.keyPersonas(msg)
		}
	}
	return m, nil
}

func (m model) keyHome(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	choose := func(i int) (tea.Model, tea.Cmd) {
		m.homeIdx = i
		if menu[i].quit {
			return m, tea.Quit
		}
		if menu[i].scr == scrHuntForm {
			m.capture = nil // a capture only rides along when arriving from Import HAR
		}
		m.open(menu[i].scr)
		return m, nil
	}
	switch k := msg.String(); k {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.homeIdx > 0 {
			m.homeIdx--
		}
	case "down", "j", "tab":
		if m.homeIdx < len(menu)-1 {
			m.homeIdx++
		}
	case "enter", " ":
		return choose(m.homeIdx)
	default:
		if len(k) == 1 && k[0] >= '1' && int(k[0]-'1') < len(menu) {
			return choose(int(k[0] - '1'))
		}
	}
	return m, nil
}

// scrollKey forwards navigation keys on a result screen to the viewport.
func (m model) scrollKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "home", "g":
		m.vp.GotoTop()
		return m, nil
	case "end", "G":
		m.vp.GotoBottom()
		return m, nil
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.w == 0 {
		return ""
	}
	if m.w < minW || m.h < minH {
		return fmt.Sprintf("\n  wafprobe needs a terminal of at least %d×%d (this one is %d×%d).\n  Enlarge the window, or press ctrl+c and use the subcommands: wafprobe -h\n",
			minW, minH, m.w, m.h)
	}
	cw := m.contentW()
	body := lipgloss.NewStyle().Height(m.bodyH()).MaxHeight(m.bodyH()).Render(m.body(cw))
	out := lipgloss.JoinVertical(lipgloss.Left, m.header(cw), "", body, "", m.footer())
	return lipgloss.NewStyle().PaddingLeft(2).MaxWidth(m.w).Render(out)
}

func (m model) crumbs() []string {
	switch m.scr {
	case scrProbeForm:
		return []string{"probe"}
	case scrProbeRun:
		return []string{"probe", "running"}
	case scrProbeResult:
		return []string{"probe", "results"}
	case scrHuntForm:
		return []string{"hunt"}
	case scrHuntRun:
		return []string{"hunt", "running"}
	case scrHuntResult:
		return []string{"hunt", "verdict"}
	case scrHARPath:
		return []string{"import HAR"}
	case scrHARPick:
		return []string{"import HAR", "pick a request"}
	case scrHARDone:
		return []string{"import HAR", "saved"}
	case scrPersonas:
		return []string{"personas"}
	}
	return nil
}

func (m model) header(cw int) string {
	left := sHead.Render("◆ wafprobe")
	for _, c := range m.crumbs() {
		left += sFaint.Render("  ›  ") + sText.Render(c)
	}
	right := sDim.Render("v" + m.version)
	gap := cw - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m model) footer() string {
	if m.flash != "" {
		if m.flashOK {
			return sPass.Render("✓ " + m.flash)
		}
		return sWarn.Render("! " + m.flash)
	}
	switch m.scr {
	case scrHome:
		return keys("↑↓", "move", "enter", "open", "1-5", "jump", "q", "quit")
	case scrProbeForm, scrHuntForm:
		return keys("enter", "run", "tab ↑↓", "next field", "←→", "change", "esc", "back")
	case scrProbeRun, scrHuntRun:
		return keys("esc", "cancel", "ctrl+c", "quit")
	case scrProbeResult:
		return keys("h", "hunt this target", "r", "re-run", "e", "export JSON", "↑↓", "scroll", "esc", "back") + m.scrollNote()
	case scrHuntResult:
		hints := []string{"r", "re-run", "d", m.deepToggleLabel(), "e", "export JSON", "↑↓", "scroll", "esc", "back"}
		if _, _, ok := bypass(m.rep); ok {
			hints = append([]string{"c", "copy curl"}, hints...)
		}
		return keys(hints...) + m.scrollNote()
	case scrHARPath:
		return keys("enter", "open", "esc", "back")
	case scrHARPick:
		return keys("type", "filter", "↑↓", "move", "enter", "capture", "esc", "back")
	case scrHARDone:
		return keys("h", "hunt with this capture", "esc", "home")
	case scrPersonas:
		return keys("↑↓", "move", "esc", "back")
	}
	return ""
}

func (m model) scrollNote() string {
	if m.vp.TotalLineCount() <= m.vp.Height {
		return ""
	}
	return sFaint.Render("  ·  ") + sDim.Render(fmt.Sprintf("%3.0f%%", m.vp.ScrollPercent()*100))
}

func (m model) body(cw int) string {
	switch m.scr {
	case scrHome:
		return m.homeView(cw)
	case scrProbeForm:
		return m.formView(cw, "Who gets blocked?",
			"Sends each selected client at the URL a few times and classifies every answer: passed, blocked, or challenged, and by which vendor.",
			m.pf, m.probeBudget())
	case scrHuntForm:
		return m.formView(cw, "What does it check?",
			"Starts from one persona, then repeats the request changing a single thing each time — TLS version, ALPN, SNI, User-Agent, headers, method. Whatever flips the answer is what the target keys on.",
			m.hf, m.huntBudget())
	case scrProbeRun:
		return m.probeRunView(cw)
	case scrHuntRun:
		return m.huntRunView(cw)
	case scrProbeResult, scrHuntResult:
		return m.vp.View()
	case scrHARPath, scrHARPick, scrHARDone:
		return m.harView(cw)
	case scrPersonas:
		return m.personasView(cw)
	}
	return ""
}

func (m model) homeView(cw int) string {
	var b strings.Builder
	b.WriteString(sBold.Render("See your traffic the way a WAF does.") + "\n")
	b.WriteString(sDim.Render(fmt.Sprintf("%d vendor detectors · %d client personas · every request is one you asked for",
		len(detect.Detectors()), len(m.personas))) + "\n\n")
	for i, it := range menu {
		num := sFaint.Render(fmt.Sprintf("%d ", i+1))
		if i == m.homeIdx {
			b.WriteString(sAccent.Render("▎ ") + num + sHead.Render(padRight(it.title, 13)) + sText.Render(it.desc) + "\n")
		} else {
			b.WriteString("  " + num + sText.Render(padRight(it.title, 13)) + sDim.Render(it.desc) + "\n")
		}
	}
	b.WriteString("\n" + sDim.Render(wrap("Only point this at systems you own or are authorised to test. A hunt sends roughly 70 requests to the target.", cw)))
	return b.String()
}

func (m model) formView(cw int, title, blurb string, f *form, budget string) string {
	var b strings.Builder
	b.WriteString(sBold.Render(title) + "\n")
	b.WriteString(sDim.Render(wrap(blurb, cw)) + "\n\n")
	b.WriteString(f.view(cw))
	if budget != "" {
		b.WriteString("\n" + strings.Repeat(" ", 2+labelW) + sDim.Render(budget))
	}
	return b.String()
}

// normalizeTarget turns "example.com" into an absolute URL.
func normalizeTarget(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", errors.New("enter a target URL")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return "", errors.New("that doesn't look like a URL — try https://example.com")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("only http:// and https:// targets are supported")
	}
	return t, nil
}

// export writes a JSON report into the working directory and reports the name.
func (m *model) export(kind, target string, write func(io.Writer) error) {
	host := "target"
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		host = strings.Map(func(r rune) rune {
			if r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				return r
			}
			return '_'
		}, u.Hostname())
	}
	name := fmt.Sprintf("wafprobe-%s-%s-%s.json", kind, host, time.Now().Format("20060102-150405"))
	f, err := os.Create(name)
	if err != nil {
		m.say(false, "could not save: %v", err)
		return
	}
	err = write(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		m.say(false, "could not save: %v", err)
		return
	}
	m.say(true, "saved %s", name)
}
