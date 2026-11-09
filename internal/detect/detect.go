// Package detect identifies which WAF or bot-management vendor served an
// HTTP response, and at which layer the request was intercepted.
package detect

import (
	"bytes"
	"net/http"
	"sort"
	"strings"
)

// Response is the subset of an *http.Response that detectors read.
type Response struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
	// Body is capped, may be truncated.
	Body       []byte
	ServerCert string

	// lowercased Body, computed once; lots of detectors do case-insensitive checks.
	lowerBody []byte
	folded    bool
}

func (r *Response) bodyHas(needle string) bool {
	if r == nil || len(r.Body) == 0 {
		return false
	}
	if !r.folded {
		r.lowerBody = bytes.ToLower(r.Body)
		r.folded = true
	}
	return bytes.Contains(r.lowerBody, []byte(strings.ToLower(needle)))
}

// FromHTTPResponse builds a Response from an *http.Response and body snapshot.
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

// Layer is where the WAF intercepted. Values go into JSON output, don't rename.
type Layer string

const (
	// handshake-level block, usually no HTTP body
	LayerTLS       Layer = "tls"
	LayerHTTP      Layer = "http"
	LayerChallenge Layer = "challenge"
	// vendor is profiling (e.g. _abck) but not blocking yet
	LayerSensor    Layer = "sensor"
	LayerRateLimit Layer = "rate-limit"
	LayerPass      Layer = "pass"
)

// Detection is the result of running detectors on a Response.
type Detection struct {
	Vendor string `json:"vendor,omitempty"`
	Layer  Layer  `json:"layer"`
	// Blocked covers denied, challenged and rate-limited.
	Blocked bool `json:"blocked"`
	// e.g. "header:cf-ray", "cookie:_abck"
	Signals []string `json:"signals,omitempty"`
	// "high" = vendor-specific token, "low" = generic inference
	Confidence string `json:"confidence,omitempty"`
	// Also holds other vendors that fired on the same response.
	Also []Detection `json:"also,omitempty"`
}

// Detector identifies one vendor; nil means no evidence.
type Detector interface {
	Vendor() string
	Detect(resp *Response) *Detection
}

var detectors []Detector

// Register adds a detector to the default set; call it from init().
func Register(d Detector) {
	detectors = append(detectors, d)
}

// Detectors returns the registered detectors sorted by vendor name.
func Detectors() []Detector {
	out := make([]Detector, len(detectors))
	copy(out, detectors)
	sort.Slice(out, func(i, j int) bool { return out[i].Vendor() < out[j].Vendor() })
	return out
}

// Analyze runs every detector and returns the most useful match. A high
// confidence blocker wins over a high confidence pass (CF in front of Akamai etc).
func Analyze(resp *Response) Detection {
	if resp == nil {
		return Detection{Layer: LayerPass}
	}

	var (
		highBlocked *Detection
		highPass    *Detection
		anyMatch    *Detection
		all         []*Detection
	)

	for _, d := range Detectors() {
		got := d.Detect(resp)
		if got == nil {
			continue
		}
		if got.Vendor == "" {
			got.Vendor = d.Vendor()
		}
		all = append(all, got)
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

	var primary *Detection
	switch {
	case highBlocked != nil:
		primary = highBlocked
	case highPass != nil:
		primary = highPass
	case anyMatch != nil:
		primary = anyMatch
	}
	if primary != nil {
		primary.Also = othersThan(all, primary)
		return *primary
	}

	layer, blocked := statusLayer(resp)
	return Detection{Layer: layer, Blocked: blocked}
}

func othersThan(all []*Detection, primary *Detection) []Detection {
	var out []Detection
	seen := map[string]bool{primary.Vendor: true}
	for _, d := range all {
		if seen[d.Vendor] {
			continue
		}
		seen[d.Vendor] = true
		out = append(out, Detection{
			Vendor: d.Vendor, Layer: d.Layer, Blocked: d.Blocked, Confidence: d.Confidence,
		})
	}
	return out
}

// verdictHeader reads the headers in which a vendor states its own decision.
// When one is present it decides the layer, whatever the status says: AWS
// serves a CAPTCHA as 405 and a Challenge as 202, and neither is a plain
// "method not allowed" or a pass.
func verdictHeader(h http.Header) (Layer, bool) {
	for _, f := range []func(http.Header) (Layer, bool){awsWAFAction, cfMitigated, vercelMitigated} {
		if layer, ok := f(h); ok {
			return layer, true
		}
	}
	return "", false
}

// benignStatus: 401/404/405-style statuses that are plain HTTP, not a WAF block.
// statusLayer checks verdictHeader first, so these never hide a vendor verdict.
func benignStatus(status int, h http.Header) bool {
	switch status {
	case 404, 405, 410, 501:
		return true
	case 401:
		return true // unauthenticated API call, not a bot block
	case 403:
		// 403 + WWW-Authenticate is auth
		return h != nil && h.Get("WWW-Authenticate") != ""
	}
	return false
}

// statusLayer maps a status to layer + blocked, benign non-2xx counts as pass.
func statusLayer(resp *Response) (Layer, bool) {
	if resp != nil {
		if layer, ok := verdictHeader(resp.Header); ok {
			return layer, true
		}
	}
	if resp != nil && benignStatus(resp.StatusCode, resp.Header) {
		return LayerPass, false
	}
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	switch {
	case code == 429:
		return LayerRateLimit, true
	case code >= 400:
		return LayerHTTP, true
	default:
		return LayerPass, false
	}
}

func layerFromStatus(code int) Layer {
	l, _ := statusLayer(&Response{StatusCode: code})
	return l
}

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
