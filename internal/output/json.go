package output

import (
	"encoding/json"
	"io"

	"github.com/NotChaosuu/wafprobe/internal/probe"
)

// JSONReport is the machine-readable payload written by JSON output mode.
type JSONReport struct {
	Tool    string          `json:"tool"`
	Version string          `json:"version"`
	Target  string          `json:"target"`
	Summary probe.Summary   `json:"summary"`
	Results []probe.Result  `json:"results"`
}

// JSON writes the full JSON report to w.
func JSON(w io.Writer, target string, results []probe.Result, version string) error {
	r := JSONReport{
		Tool:    "wafprobe",
		Version: version,
		Target:  target,
		Summary: probe.Summarize(target, results),
		Results: results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&r)
}
