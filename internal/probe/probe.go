// Package probe runs multiple TLS personas against a single target in
// parallel and classifies each response via the detect package.
package probe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/client"
	"github.com/NotChaosuu/wafprobe/internal/detect"
	"github.com/NotChaosuu/wafprobe/internal/persona"
)

// Result is the outcome of one persona hitting one target.
type Result struct {
	Persona   persona.Persona  `json:"-"`
	PersonaID string           `json:"persona_id"`
	Name      string           `json:"persona"`
	StartedAt time.Time        `json:"started_at"`
	Duration  time.Duration    `json:"duration_ms"`
	Status    int              `json:"status,omitempty"`
	Error     string           `json:"error,omitempty"`
	JA3Hash   string           `json:"ja3_hash,omitempty"`
	Detection detect.Detection `json:"detection"`
	Randomized bool            `json:"randomized,omitempty"`
}

// Options tune a probe run.
type Options struct {
	// Method defaults to GET.
	Method string
	// Headers to apply to every probe (after the persona's UA default).
	Headers http.Header
	// MaxBodyBytes caps the bytes read from response for detection.
	MaxBodyBytes int64
	// Concurrency caps parallel requests. Default 4.
	Concurrency int
	// RequestTimeout bounds each persona's entire request (dial + handshake + body).
	RequestTimeout time.Duration
	// InsecureSkipVerify disables cert validation.
	InsecureSkipVerify bool
	// Proxy, if non-nil, tunnels every probe through it.
	Proxy *url.URL
}

// Runner executes probes. Extracting this from top-level functions lets
// callers (and tests) inject transports / dependencies cleanly.
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
	return &Runner{opts: opts}
}

// RunAll runs each persona against target and returns results in persona ID order.
// The caller's ctx governs the full run; individual probes are bounded by
// opts.RequestTimeout on top of that.
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
	res := Result{
		Persona:    p,
		PersonaID:  p.ID,
		Name:       p.Name,
		StartedAt:  time.Now(),
		Randomized: p.Randomized,
	}

	// JA3 pre-compute (best-effort; failure is non-fatal since the real JA3
	// is what hits the wire). For randomized personas this is a point-in-time
	// sample and we flag it in the output.
	if _, hash, err := persona.JA3(p, hostFromTarget(target)); err == nil {
		res.JA3Hash = hash
	}

	c := client.New(p, client.Options{
		InsecureSkipVerify: r.opts.InsecureSkipVerify,
		Timeout:            r.opts.RequestTimeout,
		MaxBodyBytes:       r.opts.MaxBodyBytes,
		Proxy:              r.opts.Proxy,
	})

	req, err := http.NewRequestWithContext(ctx, r.opts.Method, target, nil)
	if err != nil {
		res.Error = err.Error()
		res.Duration = time.Since(res.StartedAt)
		return res
	}
	for k, vs := range r.opts.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.Do(req)
	res.Duration = time.Since(res.StartedAt)
	if err != nil {
		res.Error = err.Error()
		// Even transport-level errors are informative — a TLS handshake block
		// from a WAF would show up here.
		res.Detection = detect.Detection{
			Vendor:  "",
			Layer:   detect.LayerTLS,
			Blocked: true,
			Signals: []string{"transport:" + err.Error()},
			Confidence: "medium",
		}
		return res
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, r.opts.MaxBodyBytes))
	res.Status = resp.StatusCode
	res.Detection = detect.Analyze(detect.FromHTTPResponse(resp, body))
	return res
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
	Target            string   `json:"target"`
	TotalPersonas     int      `json:"total_personas"`
	Passed            int      `json:"passed"`
	Blocked           int      `json:"blocked"`
	Errored           int      `json:"errored"`
	DetectedVendors   []string `json:"detected_vendors"`
}

// Summarize returns aggregate metrics over a slice of Results.
func Summarize(target string, rs []Result) Summary {
	s := Summary{Target: target, TotalPersonas: len(rs)}
	seen := map[string]struct{}{}
	for _, r := range rs {
		if r.Error != "" {
			s.Errored++
		} else if r.Detection.Blocked {
			s.Blocked++
		} else {
			s.Passed++
		}
		if r.Detection.Vendor != "" {
			seen[r.Detection.Vendor] = struct{}{}
		}
	}
	for v := range seen {
		s.DetectedVendors = append(s.DetectedVendors, v)
	}
	return s
}
