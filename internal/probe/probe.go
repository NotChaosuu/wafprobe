// Package probe runs personas against a target in parallel and classifies the responses.
package probe

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/client"
	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// Result is the outcome of one persona hitting one target.
type Result struct {
	Persona    persona.Persona  `json:"-"`
	PersonaID  string           `json:"persona_id"`
	Name       string           `json:"persona"`
	StartedAt  time.Time        `json:"started_at"`
	Duration   time.Duration    `json:"-"`
	DurationMS int64            `json:"duration_ms"`
	Status     int              `json:"status,omitempty"`
	Error      string           `json:"error,omitempty"`
	JA3Hash    string           `json:"ja3_hash,omitempty"`
	JA4        string           `json:"ja4,omitempty"`
	JA4H       string           `json:"ja4h,omitempty"`
	HTTP2      bool             `json:"http2"`
	H2Print    string           `json:"h2_fingerprint,omitempty"` // Akamai-format HTTP/2 fingerprint
	Detection  detect.Detection `json:"detection"`
	Randomized bool             `json:"randomized,omitempty"`
	// Samples/Agree: how many runs, and how many matched the majority outcome.
	Samples int `json:"samples,omitempty"`
	Agree   int `json:"agree,omitempty"`
}

// Options tune a probe run.
type Options struct {
	Method       string
	Headers      []persona.HeaderField
	MaxBodyBytes int64
	// default 4
	Concurrency int
	// covers dial + handshake + body
	RequestTimeout     time.Duration
	InsecureSkipVerify bool
	Proxy              *url.URL
	// samples per persona for the majority vote, default 3
	Repeats int
}

// Runner executes probes.
type Runner struct {
	opts Options
}

// NewRunner builds a Runner with defaults applied.
func NewRunner(opts Options) *Runner {
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 * 1024
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 12 * time.Second
	}
	if opts.Repeats <= 0 {
		opts.Repeats = 3
	}
	return &Runner{opts: opts}
}

// RunAll runs each persona against target and returns results in persona ID order.
func (r *Runner) RunAll(ctx context.Context, target string, ps []persona.Persona) ([]Result, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("target must be an absolute URL (https://host/path)")
	}

	sem := make(chan struct{}, r.opts.Concurrency)
	out := make([]Result, len(ps))
	var wg sync.WaitGroup

	for i, p := range ps {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p persona.Persona) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = r.runOne(ctx, target, p)
		}(i, p)
	}
	wg.Wait()
	return out, nil
}

func (r *Runner) runOne(ctx context.Context, target string, p persona.Persona) Result {
	samples := make([]Result, 0, r.opts.Repeats)
	for i := 0; i < r.opts.Repeats; i++ {
		samples = append(samples, r.probeOnce(ctx, target, p))
	}
	res := voteResult(samples)

	res.Persona = p
	res.PersonaID = p.ID
	res.Name = p.Name
	res.Randomized = p.Randomized
	// JA3 varies per run for randomized personas; JA4 is order-invariant
	if _, hash, err := persona.JA3(p, hostFromTarget(target)); err == nil {
		res.JA3Hash = hash
	}
	if j4, err := persona.JA4(p, hostFromTarget(target)); err == nil {
		res.JA4 = j4
	}
	res.H2Print = persona.AkamaiH2(p)
	return res
}

func (r *Runner) probeOnce(ctx context.Context, target string, p persona.Persona) Result {
	started := time.Now()
	res := Result{StartedAt: started}
	c := client.New(p, client.Options{
		InsecureSkipVerify: r.opts.InsecureSkipVerify,
		Timeout:            r.opts.RequestTimeout,
		MaxBodyBytes:       r.opts.MaxBodyBytes,
		Proxy:              r.opts.Proxy,
		ExtraHeaders:       r.opts.Headers,
	})
	cr, err := c.Do(ctx, r.opts.Method, target, nil, "")
	res.Duration = time.Since(started)
	res.DurationMS = res.Duration.Milliseconds()
	if err != nil {
		res.Error = err.Error()
		// transport error isn't a WAF verdict; dead host, DNS and TLS reset look the same
		res.Detection = detect.Detection{
			Layer:      detect.LayerTLS,
			Blocked:    false,
			Signals:    []string{"transport:" + err.Error()},
			Confidence: "",
		}
		return res
	}
	res.Status = cr.Status
	res.HTTP2 = cr.Wire.HTTP2
	res.JA4H = cr.Wire.JA4H
	res.Detection = detect.Analyze(&detect.Response{
		StatusCode: cr.Status,
		Header:     cr.Header,
		Cookies:    cr.Cookies,
		Body:       cr.Body,
	})
	return res
}

// voteResult picks the majority class. Ties go pass > blocked > error so one
// transient error doesn't hide a real signal.
func voteResult(samples []Result) Result {
	class := func(s Result) int {
		switch {
		case s.Error != "":
			return 2 // error
		case s.Detection.Blocked:
			return 1 // blocked
		default:
			return 0 // pass
		}
	}
	counts := [3]int{}
	for _, s := range samples {
		counts[class(s)]++
	}
	winner := 0 // pass
	if counts[1] > counts[winner] {
		winner = 1
	}
	if counts[2] > counts[winner] {
		winner = 2
	}
	for _, s := range samples {
		if class(s) == winner {
			s.Samples = len(samples)
			s.Agree = counts[winner]
			return s
		}
	}
	if len(samples) > 0 {
		r := samples[0]
		r.Samples = len(samples)
		r.Agree = counts[winner]
		return r
	}
	return Result{}
}

func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// Summary returns a compact view across results.
type Summary struct {
	Target          string   `json:"target"`
	TotalPersonas   int      `json:"total_personas"`
	Passed          int      `json:"passed"`
	Blocked         int      `json:"blocked"`
	Errored         int      `json:"errored"`
	Flaky           int      `json:"flaky"` // personas whose samples didn't agree unanimously
	DetectedVendors []string `json:"detected_vendors"`
}

// Summarize returns aggregate metrics over a slice of Results.
func Summarize(target string, rs []Result) Summary {
	s := Summary{Target: target, TotalPersonas: len(rs), DetectedVendors: []string{}}
	seen := map[string]struct{}{}
	for _, r := range rs {
		if r.Error != "" {
			s.Errored++
		} else if r.Detection.Blocked {
			s.Blocked++
		} else {
			s.Passed++
		}
		if r.Samples > 1 && r.Agree < r.Samples {
			s.Flaky++
		}
		if r.Detection.Vendor != "" {
			seen[r.Detection.Vendor] = struct{}{}
		}
	}
	for v := range seen {
		s.DetectedVendors = append(s.DetectedVendors, v)
	}
	sort.Strings(s.DetectedVendors)
	return s
}
