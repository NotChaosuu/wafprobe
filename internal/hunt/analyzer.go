package hunt

import (
	"fmt"
	"sort"
	"strings"
)

// Analyze classifies axes by whether mutations on them flipped the
// baseline outcome. An axis is "checked" if at least one mutation on it
// changed a blocked baseline to pass, or a passing baseline to blocked.
func Analyze(r *Report) Findings {
	f := Findings{}

	type axisStat struct {
		flips     int
		passes    int
		blocks    int
		errors    int
		total     int
	}
	axisStats := map[string]*axisStat{}

	baselinePassed := r.BaselineOutcome == OutcomePass

	for _, res := range r.Results {
		a := res.Mutation.Axis
		s, ok := axisStats[a]
		if !ok {
			s = &axisStat{}
			axisStats[a] = s
		}
		s.total++
		switch res.Outcome {
		case OutcomePass:
			s.passes++
			if !baselinePassed {
				s.flips++
			}
			f.PassingMutations = append(f.PassingMutations, res.Mutation.Name)
		case OutcomeBlocked:
			s.blocks++
			if baselinePassed {
				s.flips++
			}
		case OutcomeError:
			s.errors++
		}
	}

	// Classify axes.
	for axis, stat := range axisStats {
		if axis == "combo" {
			continue // combo axes are reported separately
		}
		if stat.flips > 0 {
			f.Checks = append(f.Checks, axis)
		} else if stat.total > 0 && stat.errors < stat.total {
			f.Ignores = append(f.Ignores, axis)
		}
	}
	sort.Strings(f.Checks)
	sort.Strings(f.Ignores)

	// Build the Summary + Recipe.
	switch {
	case baselinePassed && len(f.Checks) == 0:
		f.Summary = "target passes with baseline persona; no tested axis mattered."
		f.Recipe = fmt.Sprintf("default client with persona %q works already.", r.Persona.ID)

	case baselinePassed && len(f.Checks) > 0:
		f.Summary = fmt.Sprintf("target passes baseline but is sensitive to mutations in: %s.",
			humanList(f.Checks))
		f.Recipe = fmt.Sprintf("keep the baseline persona (%s) and avoid the mutations above.", r.Persona.ID)

	case !baselinePassed && len(f.PassingMutations) > 0:
		f.Summary = fmt.Sprintf(
			"baseline was %s; %d mutation(s) passed. Target checks: %s. Ignores: %s.",
			r.BaselineOutcome,
			len(f.PassingMutations),
			humanList(f.Checks),
			humanList(f.Ignores),
		)
		f.Recipe = recipeFrom(r)

	default:
		f.Summary = fmt.Sprintf(
			"baseline was %s; no mutation passed. Target rejects every axis tested — likely a JS challenge.",
			r.BaselineOutcome,
		)
	}

	return f
}

func recipeFrom(r *Report) string {
	var lines []string
	for _, res := range r.Results {
		if res.Outcome != OutcomePass {
			continue
		}
		lines = append(lines, fmt.Sprintf("→ %s  (axis: %s)", res.Mutation.Name, res.Mutation.Axis))
	}
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > 5 {
		lines = append(lines[:5], fmt.Sprintf("   ... +%d more passing mutations", len(lines)-5))
	}
	return "try any of:\n  " + strings.Join(lines, "\n  ")
}

func humanList(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}
