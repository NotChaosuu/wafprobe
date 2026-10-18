// Package hunt probes a target with single-axis mutations and diffs the
// outcomes to find which fingerprint axes the WAF keys on.
package hunt

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/client"
	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// Outcome compresses a probe's result into a single enum the analyzer uses.
type Outcome int

const (
	OutcomeUnknown Outcome = iota
	// OutcomePass means the request returned a non-blocked response.
	OutcomePass
	// OutcomeBlocked means the request was denied/challenged/rate-limited.
	OutcomeBlocked
	// OutcomeError means we couldn't even complete the handshake / request.
	OutcomeError
	// OutcomeNA means the mutation couldn't be verified on the wire, so it's excluded.
	OutcomeNA
)

func (o Outcome) String() string {
	switch o {
	case OutcomePass:
		return "pass"
	case OutcomeBlocked:
		return "block"
	case OutcomeError:
		return "err"
	case OutcomeNA:
		return "n/a"
	default:
		return "?"
	}
}

// MutationResult is the outcome of one Mutation against the target.
type MutationResult struct {
	Mutation  Mutation
	Status    int
	Outcome   Outcome
	Detection detect.Detection
	Error     string
	Duration  time.Duration
	// Applied is true when the mutation was verified on the wire.
	Applied bool
	// Samples/Agree: probes for this cell and how many matched the vote.
	Samples int
	Agree   int
}

// Report is the result of a Hunt.
type Report struct {
	Target            string
	Persona           persona.Persona
	BaselineName      string
	BaselineOutcome   Outcome
	BaselineDetection detect.Detection
	BaselineStatus    int
	Results           []MutationResult
	Findings          Findings
	Duration          time.Duration
	Method            string
	Body              []byte
	Headers           []persona.HeaderField
	Cookie            string
	// Reachable is false when the baseline never completed; no verdict then.
	Reachable bool
	// BaselineFlakeRate is the fraction of baseline samples off the majority.
	BaselineFlakeRate float64
	// NoiseFloor is max(baseline flake, worst cell disagreement). a blocked
	// baseline can't show its own noise, so the verdict gates on this.
	NoiseFloor float64
	// Repeats is how many times each cell was sampled.
	Repeats int
}

// Findings is the analyzer's verdict.
type Findings struct {
	Checks           []string
	Ignores          []string
	Untested         []string // axes whose mutations couldn't be verified on the wire
	PassingMutations []string
	Recipe           string
	Summary          string
	// Unstable means the run was too noisy to split Checks/Ignores.
	Unstable bool `json:"unstable"`
}

// Options configure a Hunt run.
type Options struct {
	Persona            persona.Persona
	BaselineName       string
	PerProbeTimeout    time.Duration
	Concurrency        int
	MaxBodyBytes       int64
	InsecureSkipVerify bool
	Mutations          []Mutation
	Logger             func(idx, total int, result MutationResult)

	Method       string
	Body         []byte
	ExtraHeaders []persona.HeaderField
	Cookie       string
	Proxy        *url.URL
	BaselineALPN []string
	// Repeats is how many times to sample each cell before voting. Default 3.
	Repeats int
}

type probeOutcome struct {
	det     detect.Detection
	status  int
	outcome Outcome
	wire    client.Wire
	err     error
}

// Run executes a hunt: sampled baseline probe → mutation matrix → analyze.
func Run(ctx context.Context, target string, opts Options) (*Report, error) {
	if opts.PerProbeTimeout == 0 {
		opts.PerProbeTimeout = 10 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 * 1024
	}
	if opts.BaselineName == "" {
		opts.BaselineName = opts.Persona.ID
	}
	if opts.Mutations == nil {
		opts.Mutations = AllMutations()
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Repeats <= 0 {
		opts.Repeats = 3
	}

	start := time.Now()

	baselineOpts := client.Options{
		Timeout:            opts.PerProbeTimeout,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MaxBodyBytes:       opts.MaxBodyBytes,
		ExtraHeaders:       opts.ExtraHeaders,
		Proxy:              opts.Proxy,
		ALPNOverride:       opts.BaselineALPN,
	}
	// at least 3 baseline samples, otherwise flake can only be 0 or 0.5
	baseSampleCount := opts.Repeats
	if baseSampleCount < 3 {
		baseSampleCount = 3
	}
	baseProbe := func() probeOutcome {
		return doProbe(ctx, opts.Persona, target, opts.Method, opts.Body, opts.Cookie, baselineOpts)
	}
	baseSamples := sampleUntilStable(baseProbe, baseSampleCount, maxCellSamples)
	baseVote, baseAgree := voteOutcome(baseSamples)
	baseRep := representative(baseSamples, baseVote)

	rep := &Report{
		Target:            target,
		Persona:           opts.Persona,
		BaselineName:      opts.BaselineName,
		BaselineOutcome:   baseVote,
		BaselineDetection: baseRep.det,
		BaselineStatus:    baseRep.status,
		Duration:          0,
		Method:            opts.Method,
		Body:              opts.Body,
		Headers:           opts.ExtraHeaders,
		Cookie:            opts.Cookie,
		Reachable:         baseVote != OutcomeError,
		BaselineFlakeRate: 1 - float64(baseAgree)/float64(len(baseSamples)),
		Repeats:           opts.Repeats,
	}

	// baseline never completed: unreachable, don't invent a verdict
	if !rep.Reachable {
		rep.Duration = time.Since(start)
		rep.Findings = Findings{
			Summary: "target is unreachable: the baseline request never completed (" + baseErr(baseSamples) + "). No axis was tested.",
		}
		return rep, nil
	}

	results := make([]MutationResult, len(opts.Mutations))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	done := 0

	for i, m := range opts.Mutations {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, m Mutation) {
			defer wg.Done()
			defer func() { <-sem }()

			probeStart := time.Now()
			mOpts := client.Options{
				Timeout:            opts.PerProbeTimeout,
				InsecureSkipVerify: opts.InsecureSkipVerify,
				MaxBodyBytes:       opts.MaxBodyBytes,
				Proxy:              opts.Proxy,
				ALPNOverride:       opts.BaselineALPN,
			}
			if len(opts.ExtraHeaders) > 0 {
				mOpts.ExtraHeaders = append([]persona.HeaderField(nil), opts.ExtraHeaders...)
			}
			m.Apply(&mOpts)
			probe := func() probeOutcome {
				po := doProbe(ctx, opts.Persona, target, opts.Method, opts.Body, opts.Cookie, mOpts)
				// unverified on the wire = can't attribute
				if po.err == nil && !mutationApplied(m, mOpts, po.wire) {
					po.outcome = OutcomeNA
				}
				return po
			}
			// resample split cells up to maxCellSamples: at 3 samples one blip is 0.33,
			// over the 0.15 floor; at 7 it's ~0.14
			samples := sampleUntilStable(probe, opts.Repeats, maxCellSamples)
			vote, agree := voteOutcome(samples)
			r := representative(samples, vote)
			res := MutationResult{
				Mutation:  m,
				Status:    r.status,
				Detection: r.det,
				Duration:  time.Since(probeStart),
				Outcome:   vote,
				// n/a or error tested nothing
				Applied: vote == OutcomePass || vote == OutcomeBlocked,
				Samples: len(samples),
				Agree:   agree,
			}
			if r.err != nil {
				res.Error = r.err.Error()
			}
			results[i] = res

			if opts.Logger != nil {
				progressMu.Lock()
				done++
				n := done
				progressMu.Unlock()
				opts.Logger(n, len(opts.Mutations), res)
			}
		}(i, m)
	}
	wg.Wait()

	// re-probe the baseline at the end so flake reflects drift over the run
	allBase := append([]probeOutcome(nil), baseSamples...)
	allBase = append(allBase, sampleUntilStable(baseProbe, baseSampleCount, maxCellSamples)...)
	agree := 0
	for _, s := range allBase {
		if s.outcome == baseVote {
			agree++
		}
	}
	rep.BaselineFlakeRate = 1 - float64(agree)/float64(len(allBase))

	rep.Results = results
	// max cell disagreement, not median: with a blocked baseline only the
	// 1-2 bypass cells can disagree at all
	rep.NoiseFloor = maxFloat(rep.BaselineFlakeRate, maxCellFlake(results))

	rep.Duration = time.Since(start)
	rep.Findings = Analyze(rep)
	return rep, nil
}

func doProbe(ctx context.Context, p persona.Persona, target, method string, body []byte, cookie string, opts client.Options) probeOutcome {
	c := client.New(p, opts)
	cr, err := c.Do(ctx, method, target, body, cookie)
	if err != nil {
		return probeOutcome{err: err, outcome: OutcomeError}
	}
	det := detect.Analyze(&detect.Response{
		StatusCode: cr.Status,
		Header:     cr.Header,
		Cookies:    cr.Cookies,
		Body:       cr.Body,
	})
	return probeOutcome{
		det:     det,
		status:  cr.Status,
		outcome: outcomeFrom(det, err),
		wire:    cr.Wire,
	}
}

// mutationApplied reports whether a mutation took effect on the wire. TLS
// version and ALPN are negotiated, so they're checked against the read-back.
func mutationApplied(m Mutation, opts client.Options, w client.Wire) bool {
	switch m.Axis {
	case "tls-version":
		// ClientHello only offers the forced version; resp.TLS isn't exposed on h2
		return w.SpecMutated
	case "alpn":
		switch {
		case len(opts.ALPNOverride) == 1 && opts.ALPNOverride[0] == "h2":
			return w.HTTP2
		case len(opts.ALPNOverride) == 1 && opts.ALPNOverride[0] == "http/1.1":
			return !w.HTTP2
		default:
			return true // empty ALPN list: removed from the ClientHello by construction
		}
	case "sni":
		// HelloGolang can't omit SNI
		return w.SNIOmitted
	case "combo":
		// http/1.1 combos must show the downgrade
		if len(opts.ALPNOverride) == 1 && opts.ALPNOverride[0] == "http/1.1" {
			return !w.HTTP2
		}
		return true
	default:
		return true
	}
}

// outcomeFrom classifies a completed probe into pass/block. Non-2xx that the
// detect layer treats as benign (a 404/405/401) is a pass, not a block.
func outcomeFrom(det detect.Detection, err error) Outcome {
	if err != nil {
		return OutcomeError
	}
	if det.Blocked {
		return OutcomeBlocked
	}
	return OutcomePass
}

// voteOutcome returns the majority outcome and how many samples agreed.
func voteOutcome(samples []probeOutcome) (Outcome, int) {
	counts := map[Outcome]int{}
	for _, s := range samples {
		counts[s.outcome]++
	}
	best, bestN := OutcomeUnknown, -1
	// tie-break: pass > block > n/a > error > unknown
	for _, o := range []Outcome{OutcomePass, OutcomeBlocked, OutcomeNA, OutcomeError, OutcomeUnknown} {
		if counts[o] > bestN {
			best, bestN = o, counts[o]
		}
	}
	return best, counts[best]
}

// representative returns a sample matching the voted outcome, else the first.
func representative(samples []probeOutcome, vote Outcome) probeOutcome {
	for _, s := range samples {
		if s.outcome == vote {
			return s
		}
	}
	if len(samples) > 0 {
		return samples[0]
	}
	return probeOutcome{}
}

// maxCellSamples caps how far a dissenting cell (or baseline) is resampled.
const maxCellSamples = 7

// sampleUntilStable probes minN times, then up to maxN while results disagree.
func sampleUntilStable(probe func() probeOutcome, minN, maxN int) []probeOutcome {
	if minN < 1 {
		minN = 1
	}
	if maxN < minN {
		maxN = minN
	}
	out := make([]probeOutcome, 0, maxN)
	for i := 0; i < minN; i++ {
		out = append(out, probe())
	}
	for len(out) < maxN && !unanimousOutcome(out) {
		out = append(out, probe())
	}
	return out
}

func unanimousOutcome(ss []probeOutcome) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i].outcome != ss[0].outcome {
			return false
		}
	}
	return true
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// maxCellFlake is the worst 1-agree/samples across mutation cells.
func maxCellFlake(results []MutationResult) float64 {
	max := 0.0
	for _, r := range results {
		if r.Samples > 1 {
			if f := 1 - float64(r.Agree)/float64(r.Samples); f > max {
				max = f
			}
		}
	}
	return max
}

func baseErr(samples []probeOutcome) string {
	for _, s := range samples {
		if s.err != nil {
			return s.err.Error()
		}
	}
	return "no response"
}
