package detect

// Kasada detector.
//
// Kasada serves a JS sensor at /ips.js. Clients that solve the challenge
// must echo x-kpsdk-ct (token) and x-kpsdk-cd (data) on every protected
// request; we can only detect those header NAMES being referenced, we can't
// generate valid values.
//
// Server-side signals: x-kpsdk-v / x-kpsdk-cd / x-kpsdk-im response headers,
// KP_UIDz cookie, /ips.js script reference in body. 429 is Kasada's default
// block status (most other vendors use 403/503), so we map 429+kasada-sig
// to LayerHTTP rather than LayerRateLimit.

type kasada struct{}

func (kasada) Vendor() string { return "kasada" }

func (kasada) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

	for name := range resp.Header {
		if hasPrefixFold(name, "X-KPSDK-") {
			signals = append(signals, "header:"+name)
		}
	}
	if _, ok := hasCookie(resp.Cookies, "KP_UIDz"); ok {
		signals = append(signals, "cookie:KP_UIDz")
	}
	if _, ok := hasCookie(resp.Cookies, "KP_UIDz-ssn"); ok {
		signals = append(signals, "cookie:KP_UIDz-ssn")
	}
	if bodyContains(resp.Body, "/ips.js") {
		signals = append(signals, "body:kasada-ips.js")
	}
	if bodyContains(resp.Body, "kpsdk") || bodyContains(resp.Body, "kasada") {
		signals = append(signals, "body:kasada-string")
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "kasada",
		Confidence: "high",
		Signals:    signals,
	}

	switch {
	case resp.StatusCode == 429:
		// Kasada uses 429 as default block, not rate-limit.
		det.Layer = LayerHTTP
		det.Blocked = true
	case resp.StatusCode == 403:
		det.Layer = LayerHTTP
		det.Blocked = true
	case bodyContains(resp.Body, "/ips.js") && resp.StatusCode == 200:
		// Sensor injected on a passing page; not blocked, but watched.
		det.Layer = LayerSensor
		det.Blocked = false
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}

	return det
}

func init() { Register(kasada{}) }
