package hunt

import (
	"fmt"
	"sort"
	"strings"
)

// Analyze buckets axes into checked / ignored / untested based on whether
// verified mutations flipped the baseline outcome.
func Analyze(r *Report) Findings {
	// non-nil so JSON gets [] not null
	f := Findings{Checks: []string{}, Ignores: []string{}, Untested: []string{}, PassingMutations: []string{}}
	if !r.Reachable {
		return f // caller already set an unreachable summary
	}

	type axisStat struct {
		flips    int
		verified int // probes whose mutation was applied and completed (pass/block)
		untested int // probes that couldn't be verified on the wire (n/a)
		errors   int
		total    int
	}
	axisStats := map[string]*axisStat{}
	baselinePassed := r.BaselineOutcome == OutcomePass

	for _, res := range r.Results {
		a := res.Mutation.Axis
		if a == "combo" {
			if res.Outcome == OutcomePass {
				f.PassingMutations = append(f.PassingMutations, res.Mutation.Name)
			}
			continue
		}
		s, ok := axisStats[a]
		if !ok {
			s = &axisStat{}
			axisStats[a] = s
		}
		s.total++
		switch res.Outcome {
		case OutcomeNA:
			s.untested++
		case OutcomeError:
			s.errors++
		case OutcomePass:
			s.verified++
			if !baselinePassed {
				s.flips++
			}
			f.PassingMutations = append(f.PassingMutations, res.Mutation.Name)
		case OutcomeBlocked:
			s.verified++
			if baselinePassed {
				s.flips++
			}
		}
	}

	// too noisy to attribute; NoiseFloor also covers a constant-block baseline
	const unstableFlake = 0.15
	noise := r.NoiseFloor
	if noise >= unstableFlake {
		f.Unstable = true
		f.Checks, f.Ignores, f.Untested = []string{}, []string{}, []string{}
		f.Summary = fmt.Sprintf(
			"target is unstable — it answered the same request inconsistently (worst cell %.0f%% disagreement across samples), so no axis can be attributed reliably. It's likely rate-limiting or scoring by IP reputation; re-run, slow down, or probe from a cleaner IP.",
			noise*100)
		return f
	}
	for axis, stat := range axisStats {
		flipRate := 0.0
		if stat.verified > 0 {
			flipRate = float64(stat.flips) / float64(stat.verified)
		}
		switch {
		case stat.verified == 0:
			// nothing verified on this axis
			f.Untested = append(f.Untested, axis)
		case stat.flips > 0 && flipRate > noise:
			f.Checks = append(f.Checks, axis)
		default:
			f.Ignores = append(f.Ignores, axis)
		}
	}
	sort.Strings(f.Checks)
	sort.Strings(f.Ignores)
	sort.Strings(f.Untested)

	trust := ""
	if noise > 0 {
		trust = fmt.Sprintf(" Noise floor %.0f%% — treat borderline axes with care.", noise*100)
	}
	untested := ""
	if len(f.Untested) > 0 {
		untested = fmt.Sprintf(" Untested (couldn't confirm on the wire): %s.", humanList(f.Untested))
	}

	switch {
	case baselinePassed && len(f.Checks) == 0:
		f.Summary = "target passes with baseline persona; no tested axis mattered." + untested + trust
		f.Recipe = fmt.Sprintf("default client with persona %q works already.", r.Persona.ID)

	case baselinePassed && len(f.Checks) > 0:
		f.Summary = fmt.Sprintf("target passes baseline but is sensitive to mutations in: %s.%s%s",
			humanList(f.Checks), untested, trust)
		f.Recipe = fmt.Sprintf("keep the baseline persona (%s) and avoid the mutations above.", r.Persona.ID)

	case !baselinePassed && len(f.PassingMutations) > 0:
		f.Summary = fmt.Sprintf(
			"baseline was %s; %d mutation(s) passed. Checks: %s. Ignores: %s.%s%s",
			r.BaselineOutcome, len(f.PassingMutations), humanList(f.Checks), humanList(f.Ignores), untested, trust)
		f.Recipe = recipeFrom(r)

	default:
		f.Summary = fmt.Sprintf(
			"baseline was %s; no verified mutation passed. Every tested axis was rejected — likely a JS challenge or a hard block.%s%s",
			r.BaselineOutcome, untested, trust)
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
