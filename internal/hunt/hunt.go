// Package hunt runs a baseline probe plus N axis-mutation probes against a
// target URL, then diffs the outcomes to identify which fingerprint axes
// (TLS version, ALPN, SNI, UA, cookies, headers, method) the WAF is using.
package hunt

import (
	"context"
	"io"
	"net/http"
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
	// OutcomePass means the request returned a non-blocked 2xx response.
	OutcomePass
	// OutcomeBlocked means the request was denied/challenged/rate-limited.
	OutcomeBlocked
	// OutcomeError means we couldn't even complete the handshake / request.
	OutcomeError
)

func (o Outcome) String() string {
	switch o {
	case OutcomePass:
		return "pass"
	case OutcomeBlocked:
		return "block"
	case OutcomeError:
		return "err"
	default:
		return "?"
	}
}

// MutationResult is the outcome of one Mutation against the target.
type MutationResult struct {
	Mutation    Mutation
	Status      int
	Outcome     Outcome
	Detection   detect.Detection
	Error       string
	Duration    time.Duration
}

// Report is the result of a Hunt: baseline, per-mutation results, findings.
// Method/Body/Headers/Cookie are echoed so the curl emitter can reproduce
// the exact request that was sent.
type Report struct {
	Target        string
	Persona       persona.Persona
	BaselineName  string
	BaselineOutcome Outcome
	BaselineDetection detect.Detection
	BaselineStatus int
	Results       []MutationResult
	Findings      Findings
	Duration      time.Duration
	Method  string
	Body    []byte
	Headers map[string]string
	Cookie  string
}

// Findings is the analyzer's verdict.
type Findings struct {
	// Checks lists axis names that, when mutated, changed the outcome.
	Checks []string
	// Ignores lists axis names where mutation had no effect.
	Ignores []string
	// PassingMutations are single mutations that produced a pass.
	PassingMutations []string
	// Recipe is a copy-paste bypass suggestion when one can be derived.
	Recipe string
	// Summary is a one-sentence conclusion.
	Summary string
}

// Options configure a Hunt run.
type Options struct {
	Persona            persona.Persona
	BaselineName       string
	PerProbeTimeout    time.Duration
	// Concurrency caps parallel mutations. Default 4.
	Concurrency        int
	MaxBodyBytes       int64
	InsecureSkipVerify bool
	// Mutations to run. nil = AllMutations().
	Mutations []Mutation
	// Logger receives per-probe progress updates.
	Logger func(idx, total int, result MutationResult)

	// Base request shape — applied to baseline AND every mutation.
	Method       string
	Body         []byte
	ExtraHeaders map[string]string
	Cookie       string
	Proxy        *url.URL
	// BaselineALPN forces ALPN protocols on every probe. Use ["http/1.1"]
	// to force HTTP/1.1 across the whole run.
	BaselineALPN []string
}

// Run executes a hunt: baseline probe → mutation matrix → analyze.
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
		opts.Method = http.MethodGet
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
	baseDet, baseStatus, baseErr := doProbe(ctx, opts.Persona, target, opts.Method, opts.Body, opts.Cookie, baselineOpts)
	baseOutcome := outcomeFrom(baseDet, baseStatus, baseErr)

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
				ALPNOverride:       opts.BaselineALPN, // mutation may further override below
			}
			// Carry over base-level extra headers so per-mutation Apply can extend them.
			if opts.ExtraHeaders != nil {
				mOpts.ExtraHeaders = map[string]string{}
				for k, v := range opts.ExtraHeaders {
					mOpts.ExtraHeaders[k] = v
				}
			}
			m.Apply(&mOpts)
			det, status, err := doProbe(ctx, opts.Persona, target, opts.Method, opts.Body, opts.Cookie, mOpts)
			res := MutationResult{
				Mutation:  m,
				Status:    status,
				Detection: det,
				Duration:  time.Since(probeStart),
				Outcome:   outcomeFrom(det, status, err),
			}
			if err != nil {
				res.Error = err.Error()
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

	rep := &Report{
		Target:            target,
		Persona:           opts.Persona,
		BaselineName:      opts.BaselineName,
		BaselineOutcome:   baseOutcome,
		BaselineDetection: baseDet,
		BaselineStatus:    baseStatus,
		Results:           results,
		Duration:          time.Since(start),
		Method:            opts.Method,
		Body:              opts.Body,
		Headers:           opts.ExtraHeaders,
		Cookie:            opts.Cookie,
	}

	rep.Findings = Analyze(rep)
	return rep, nil
}

func doProbe(ctx context.Context, p persona.Persona, target, method string, body []byte, cookie string, opts client.Options) (detect.Detection, int, error) {
	c := client.New(p, opts)
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytesReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return detect.Detection{}, 0, err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		return detect.Detection{}, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	det := detect.Analyze(detect.FromHTTPResponse(resp, respBody))
	return det, resp.StatusCode, nil
}

// bytesReader returns a fresh io.Reader for body bytes (one per call so
// concurrent probes don't share state).
func bytesReader(b []byte) io.Reader {
	return &bytesReaderImpl{buf: b}
}

type bytesReaderImpl struct {
	buf []byte
	off int
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// outcomeFrom classifies a probe into one of {pass, block, error}.
func outcomeFrom(det detect.Detection, status int, err error) Outcome {
	if err != nil {
		return OutcomeError
	}
	if det.Blocked {
		return OutcomeBlocked
	}
	if status >= 400 {
		return OutcomeBlocked
	}
	return OutcomePass
}
