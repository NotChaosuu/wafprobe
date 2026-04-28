// Package detect identifies which WAF or bot-management vendor served an
// HTTP response, and at which layer the request was intercepted.
package detect

import (
	"net/http"
	"sort"
	"strings"
)

// Response is the subset of an *http.Response that detectors consume.
// Decoupling lets tests build fixtures without standing up an HTTP server.
type Response struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
	// Body is a capped snapshot — detectors must not assume it's complete.
	Body       []byte
	ServerCert string
}

// FromHTTPResponse builds a Response from an *http.Response + body snapshot.
func FromHTTPResponse(r *http.Response, body []byte) *Response {
	if r == nil {
		return nil
	}
	var cookies []*http.Cookie
	if r.Header != nil {
		cookies = r.Cookies()
	}
	return &Response{
		StatusCode: r.StatusCode,
		Header:     r.Header,
		Cookies:    cookies,
		Body:       body,
	}
}

// Layer is where in the request lifecycle the WAF intercepted.
// Values appear in JSON output; do not rename without a schema bump.
type Layer string

const (
	// LayerTLS — handshake-level block (rare; usually leaves no HTTP body).
	LayerTLS Layer = "tls"
	// LayerHTTP — 4xx/5xx block page.
	LayerHTTP Layer = "http"
	// LayerChallenge — JS/captcha interstitial.
	LayerChallenge Layer = "challenge"
	// LayerSensor — vendor is profiling (e.g. _abck seed) but not blocking yet.
	LayerSensor Layer = "sensor"
	// LayerRateLimit — 429.
	LayerRateLimit Layer = "rate-limit"
	// LayerPass — request got through.
	LayerPass Layer = "pass"
)

// Detection is the result of running detectors on a Response.
type Detection struct {
	// Vendor identified, or "" if none matched.
	Vendor string `json:"vendor,omitempty"`
	// Layer where the request was intercepted.
	Layer Layer `json:"layer"`
	// Blocked is true for denied / challenged / rate-limited responses.
	Blocked bool `json:"blocked"`
	// Signals lists what matched (e.g. "header:cf-ray", "cookie:_abck").
	Signals []string `json:"signals,omitempty"`
	// Confidence: "high" = vendor-specific token, "low" = generic inference.
	Confidence string `json:"confidence,omitempty"`
}

// Detector identifies one vendor in a Response. Returns nil when no
// evidence of that vendor is present, so Analyze can chain them cheaply.
type Detector interface {
	Vendor() string
	Detect(resp *Response) *Detection
}

var detectors []Detector

// Register adds a detector to the default set used by Analyze.
// Packages containing detectors call this from init().
func Register(d Detector) {
	detectors = append(detectors, d)
}

// Detectors returns the registered detectors sorted by vendor name (deterministic).
func Detectors() []Detector {
	out := make([]Detector, len(detectors))
	copy(out, detectors)
	sort.Slice(out, func(i, j int) bool { return out[i].Vendor() < out[j].Vendor() })
	return out
}

// Analyze runs every registered detector against resp and returns the
// most informative match. Precedence: high-confidence Blocked > high
// pass > first match > pass-through. If multiple high-confidence
// detectors fire (e.g. CF in front of an Akamai origin), the BLOCKER wins
// because that's what the caller needs to address.
func Analyze(resp *Response) Detection {
	if resp == nil {
		return Detection{Layer: LayerPass}
	}

	var (
		highBlocked *Detection
		highPass    *Detection
		anyMatch    *Detection
	)

	for _, d := range Detectors() {
		got := d.Detect(resp)
		if got == nil {
			continue
		}
		if got.Vendor == "" {
			got.Vendor = d.Vendor()
		}
		if got.Confidence == "high" {
			if got.Blocked && highBlocked == nil {
				highBlocked = got
			}
			if !got.Blocked && highPass == nil {
				highPass = got
			}
		}
		if anyMatch == nil {
			anyMatch = got
		}
	}

	switch {
	case highBlocked != nil:
		return *highBlocked
	case highPass != nil:
		return *highPass
	case anyMatch != nil:
		return *anyMatch
	}

	return Detection{Layer: layerFromStatus(resp.StatusCode), Blocked: resp.StatusCode >= 400}
}

func layerFromStatus(code int) Layer {
	switch {
	case code == 429:
		return LayerRateLimit
	case code >= 400:
		return LayerHTTP
	default:
		return LayerPass
	}
}

// Helpers shared across vendor detectors.

func hasHeader(h http.Header, name string) (string, bool) {
	if h == nil {
		return "", false
	}
	v := h.Get(name)
	return v, v != ""
}

func hasCookie(cs []*http.Cookie, name string) (string, bool) {
	for _, c := range cs {
		if strings.EqualFold(c.Name, name) {
			return c.Value, true
		}
	}
	return "", false
}

func bodyContains(b []byte, needle string) bool {
	if len(b) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(needle))
}
