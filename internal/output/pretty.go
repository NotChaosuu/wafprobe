// Package output renders probe results to a stream (stdout or a file) in
// either a human-readable pretty format or JSON.
package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

// colourEnabled reports whether ANSI codes should be emitted for w.
// True only for terminal writers without NO_COLOR set; tests always get
// plain output because they write to bytes.Buffer.
func colourEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Codes is the minimal ANSI set we use. Kept in a small struct so callers
// (including tests) can swap them off.
type Codes struct {
	Reset, Bold, Dim, Red, Yellow, Green, Cyan string
}

func newCodes(enabled bool) Codes {
	if !enabled {
		return Codes{}
	}
	return Codes{
		Reset: "\x1b[0m", Bold: "\x1b[1m", Dim: "\x1b[2m",
		Red: "\x1b[31m", Yellow: "\x1b[33m", Green: "\x1b[32m", Cyan: "\x1b[36m",
	}
}

// Pretty writes a human-readable report to w.
func Pretty(w io.Writer, target string, results []probe.Result, version string) error {
	c := newCodes(colourEnabled(w))

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%swafprobe v%s%s  %starget: %s%s\n", c.Bold, c.Cyan, version, c.Reset, c.Dim, target, c.Reset)
	fmt.Fprintln(w, divider(c))
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "  %sPERSONA\tSTATUS\tVENDOR\tLAYER\tDETAIL%s\n", c.Bold, c.Reset)
	for _, r := range results {
		fmt.Fprintln(tw, rowFor(r, c))
	}
	_ = tw.Flush()

	fmt.Fprintln(w)
	s := probe.Summarize(target, results)
	fmt.Fprintf(w, "  %sSummary:%s  %s%d passed%s, %s%d blocked%s, %s%d errored%s  (%d personas total)\n",
		c.Bold, c.Reset,
		c.Green, s.Passed, c.Reset,
		c.Red, s.Blocked, c.Reset,
		c.Yellow, s.Errored, c.Reset,
		s.TotalPersonas,
	)
	if len(s.DetectedVendors) > 0 {
		fmt.Fprintf(w, "  %sVendors seen:%s %s\n", c.Bold, c.Reset, strings.Join(s.DetectedVendors, ", "))
	}
	fmt.Fprintln(w)
	return nil
}

func divider(c Codes) string {
	return c.Dim + strings.Repeat("─", 58) + c.Reset
}

func rowFor(r probe.Result, c Codes) string {
	status := fmt.Sprintf("%d", r.Status)
	if r.Error != "" {
		status = "ERR"
	}

	vendor := r.Detection.Vendor
	if vendor == "" {
		vendor = "-"
	}
	layer := string(r.Detection.Layer)
	if layer == "" {
		layer = "-"
	}

	// color the layer cell based on pass/blocked
	layerCell := layer
	switch {
	case r.Error != "":
		layerCell = c.Yellow + layer + c.Reset
	case r.Detection.Blocked:
		layerCell = c.Red + layer + c.Reset
	case layer == "pass":
		layerCell = c.Green + layer + c.Reset
	}

	detail := truncate(firstSignal(r), 50)
	if r.Error != "" {
		detail = truncate(r.Error, 50)
	}

	return fmt.Sprintf("  %s\t%s\t%s\t%s\t%s", r.PersonaID, status, vendor, layerCell, detail)
}

// firstSignal picks the most informative signal for the DETAIL column.
// Priority: body > cookie > non-cf-ray header > cf-ray > whatever's first.
// cf-ray is demoted because the VENDOR column already shows "cloudflare";
// the body signature tells you which CF mechanism (Turnstile vs Managed),
// which is the actually useful detail.
func firstSignal(r probe.Result) string {
	sigs := r.Detection.Signals
	if len(sigs) == 0 {
		if r.Detection.Layer == detect.LayerPass {
			return "clean"
		}
		return "-"
	}
	// Walk by descending priority.
	priorities := [][]string{
		{"body:", "transport:"},
		{"cookie:"},
		{"header:"},
	}
	// cf-ray is common to every Cloudflare response; demote it to a tiebreaker.
	demotable := func(s string) bool {
		return strings.HasPrefix(strings.ToLower(s), "header:cf-ray")
	}
	for _, prefixes := range priorities {
		for _, s := range sigs {
			for _, p := range prefixes {
				if strings.HasPrefix(strings.ToLower(s), p) && !demotable(s) {
					return s
				}
			}
		}
	}
	return sigs[0]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
