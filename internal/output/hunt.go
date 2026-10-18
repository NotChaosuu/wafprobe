package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/NotChaosuu/wafprobe/internal/hunt"
)

// HuntPretty renders a hunt.Report as a human-readable terminal report.
func HuntPretty(w io.Writer, r *hunt.Report, version string) error {
	c := newCodes(colourEnabled(w))

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%swafprobe hunt v%s%s  %starget: %s%s\n",
		c.Bold, c.Cyan, version, c.Reset, c.Dim, r.Target, c.Reset)
	fmt.Fprintln(w, divider(c))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  %sbaseline%s (%s): %s — %s\n",
		c.Bold, c.Reset,
		r.BaselineName,
		outcomeColoured(r.BaselineOutcome, c),
		vendorOrNone(r.BaselineDetection.Vendor, c),
	)
	if r.Repeats > 0 {
		var flakeNote string
		switch {
		case r.Repeats < 2:
			// one sample can't be called stable
			flakeNote = "stability not measured (1 sample per cell)"
		case r.NoiseFloor > 0:
			flakeNote = fmt.Sprintf("%.0f%% flake", r.NoiseFloor*100)
		default:
			flakeNote = "stable"
		}
		fmt.Fprintf(w, "  %ssampled %d× per cell · %s%s\n", c.Dim, r.Repeats, flakeNote, c.Reset)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  %ssurgical axis mutations%s (%d probes)\n", c.Bold, c.Reset, len(r.Results))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s%-36s  %-12s  %-6s%s\n", c.Dim, "MUTATION", "AXIS", "RESULT", c.Reset)
	for _, res := range r.Results {
		nameCol := truncate(res.Mutation.Name, 36)
		outcome := outcomeColoured(res.Outcome, c)
		extra := ""
		if res.Outcome == OutcomeAlias(hunt.OutcomeError) && res.Error != "" {
			extra = "  " + c.Dim + "err: " + truncate(res.Error, 40) + c.Reset
		}
		fmt.Fprintf(w, "  %-36s  %-12s  %-6s%s\n", nameCol, res.Mutation.Axis, outcome, extra)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, boxTop(c, "REVERSE-ENGINEERED", 58))
	writeBoxLine(w, c, 58, "")
	if r.Findings.Unstable {
		// too flaky to attribute
		writeBoxLine(w, c, 58, fmt.Sprintf("  %sRun unstable — no axis attribution%s", c.Yellow, c.Reset))
	} else {
		writeBoxLine(w, c, 58, fmt.Sprintf("  %sTarget checks:%s  %s", c.Bold, c.Reset, humanList(r.Findings.Checks, c.Green)))
		writeBoxLine(w, c, 58, fmt.Sprintf("  %sTarget ignores:%s %s", c.Bold, c.Reset, humanList(r.Findings.Ignores, c.Dim)))
		if len(r.Findings.Untested) > 0 {
			writeBoxLine(w, c, 58, fmt.Sprintf("  %sUntested (unverified):%s %s", c.Bold, c.Reset, humanList(r.Findings.Untested, c.Yellow)))
		}
	}
	writeBoxLine(w, c, 58, "")
	if r.Findings.Recipe != "" {
		writeBoxLine(w, c, 58, fmt.Sprintf("  %sBypass recipe:%s", c.Bold, c.Reset))
		for _, line := range strings.Split(r.Findings.Recipe, "\n") {
			writeBoxLine(w, c, 58, "    "+line)
		}
		writeBoxLine(w, c, 58, "")
	}
	writeBoxLine(w, c, 58, fmt.Sprintf("  %sVerdict:%s %s", c.Bold, c.Reset, r.Findings.Summary))
	writeBoxLine(w, c, 58, "")
	fmt.Fprintln(w, boxBottom(c, 58))
	fmt.Fprintln(w)

	// curl recipe for first passing mutation; skipped on unstable runs (likely luck)
	for _, res := range r.Results {
		if r.Findings.Unstable {
			break
		}
		if res.Outcome != hunt.OutcomePass {
			continue
		}
		if r.BaselineOutcome != hunt.OutcomeBlocked {
			break
		}
		fmt.Fprintf(w, "  %s%sready-to-run curl for first passing mutation (%s):%s\n",
			c.Bold, c.Cyan, res.Mutation.Name, c.Reset)
		fmt.Fprintln(w)
		curl := hunt.CurlFor(r.Target, r.Method, r.Persona.UserAgent, r.Cookie, r.Body, r.Headers, res.Mutation)
		for _, line := range strings.Split(curl, "\n") {
			fmt.Fprintf(w, "    %s\n", line)
		}
		fmt.Fprintln(w)
		break
	}
	return nil
}

// HuntJSON writes the full hunt report as JSON.
func HuntJSON(w io.Writer, r *hunt.Report, version string) error {
	type mutationJSON struct {
		Name     string `json:"name"`
		Axis     string `json:"axis"`
		Status   int    `json:"status,omitempty"`
		Outcome  string `json:"outcome"`
		Applied  bool   `json:"applied"`
		Samples  int    `json:"samples,omitempty"`
		Agree    int    `json:"agree,omitempty"`
		Vendor   string `json:"vendor,omitempty"`
		Layer    string `json:"layer,omitempty"`
		Blocked  bool   `json:"blocked"`
		Error    string `json:"error,omitempty"`
		Duration int64  `json:"duration_ms"`
	}
	type reportJSON struct {
		Tool            string         `json:"tool"`
		Version         string         `json:"version"`
		Target          string         `json:"target"`
		Persona         string         `json:"persona"`
		Reachable       bool           `json:"reachable"`
		Complete        bool           `json:"complete"`
		BaselineOutcome string         `json:"baseline_outcome"`
		BaselineStatus  int            `json:"baseline_status"`
		BaselineVendor  string         `json:"baseline_vendor,omitempty"`
		BaselineFlake   float64        `json:"baseline_flake_rate"`
		NoiseFloor      float64        `json:"noise_floor"`
		Repeats         int            `json:"repeats"`
		Mutations       []mutationJSON `json:"mutations"`
		Findings        hunt.Findings  `json:"findings"`
		DurationMS      int64          `json:"duration_ms"`
	}
	muts := make([]mutationJSON, len(r.Results))
	for i, res := range r.Results {
		muts[i] = mutationJSON{
			Name:     res.Mutation.Name,
			Axis:     res.Mutation.Axis,
			Status:   res.Status,
			Outcome:  res.Outcome.String(),
			Applied:  res.Applied,
			Samples:  res.Samples,
			Agree:    res.Agree,
			Vendor:   res.Detection.Vendor,
			Layer:    string(res.Detection.Layer),
			Blocked:  res.Detection.Blocked,
			Error:    res.Error,
			Duration: res.Duration.Milliseconds(),
		}
	}
	rep := reportJSON{
		Tool:            "wafprobe",
		Version:         version,
		Target:          r.Target,
		Persona:         r.Persona.ID,
		Reachable:       r.Reachable,
		Complete:        r.Reachable,
		BaselineOutcome: r.BaselineOutcome.String(),
		BaselineStatus:  r.BaselineStatus,
		BaselineVendor:  r.BaselineDetection.Vendor,
		BaselineFlake:   r.BaselineFlakeRate,
		NoiseFloor:      r.NoiseFloor,
		Repeats:         r.Repeats,
		Mutations:       muts,
		Findings:        r.Findings,
		DurationMS:      r.Duration.Milliseconds(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&rep)
}

// OutcomeAlias re-exports hunt.Outcome.
type OutcomeAlias = hunt.Outcome

func outcomeColoured(o hunt.Outcome, c Codes) string {
	switch o {
	case hunt.OutcomePass:
		return c.Green + "pass" + c.Reset
	case hunt.OutcomeBlocked:
		return c.Red + "block" + c.Reset
	case hunt.OutcomeError:
		return c.Yellow + "err" + c.Reset
	case hunt.OutcomeNA:
		return c.Dim + "n/a" + c.Reset
	default:
		return "?"
	}
}

func vendorOrNone(v string, c Codes) string {
	if v == "" {
		return c.Dim + "(no vendor signature)" + c.Reset
	}
	return c.Cyan + v + c.Reset
}

func humanList(xs []string, color string) string {
	if len(xs) == 0 {
		return color + "(none)" + ""
	}
	return color + strings.Join(xs, ", ") + ""
}

func boxTop(c Codes, title string, width int) string {
	inner := width - len(title) - 4
	left := inner / 2
	right := inner - left
	return c.Dim + "╔" + strings.Repeat("═", left) + " " + c.Reset + c.Bold + title + c.Reset + c.Dim + " " + strings.Repeat("═", right) + "╗" + c.Reset
}

func boxBottom(c Codes, width int) string {
	return c.Dim + "╚" + strings.Repeat("═", width-2) + "╝" + c.Reset
}

func writeBoxLine(w io.Writer, c Codes, width int, content string) {
	stripped := stripANSI(content)
	// measure in runes so "—" / "→" don't throw off padding
	inner := width - 2
	if utf8.RuneCountInString(stripped) <= inner {
		pad := inner - utf8.RuneCountInString(stripped)
		fmt.Fprintf(w, "%s║%s%s%s%s║%s\n", c.Dim, c.Reset, content, strings.Repeat(" ", pad), c.Dim, c.Reset)
		return
	}
	// wrap on words by rune length; colour is dropped on continuation lines
	words := strings.Fields(stripped)
	if len(words) == 0 {
		words = []string{stripped}
	}
	lines := []string{}
	cur := ""
	for _, word := range words {
		if utf8.RuneCountInString(cur)+utf8.RuneCountInString(word)+1 > inner {
			lines = append(lines, cur)
			cur = "  " + word // hanging indent
		} else if cur == "" {
			cur = word
		} else {
			cur += " " + word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	for _, line := range lines {
		lw := utf8.RuneCountInString(line)
		pad := inner - lw
		if pad < 0 {
			pad = 0
			line = string([]rune(line)[:inner])
		}
		fmt.Fprintf(w, "%s║%s%s%s%s║%s\n", c.Dim, c.Reset, line, strings.Repeat(" ", pad), c.Dim, c.Reset)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
