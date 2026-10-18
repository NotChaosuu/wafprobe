package detect

import "strings"

// Akamai detector. "akamai" (high) means Bot Manager cookies/sensor_data;
// "akamai-cdn" (low) means only AkamaiGHost / X-Akamai-* headers, which say
// nothing about bot protection.
//
// _abck is "~"-delimited; field 1 is -1 while the sensor is still profiling
// and 0 once validated. Blocks come from the status, not the cookie.

type akamai struct{}

func (akamai) Vendor() string { return "akamai" }

func (akamai) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}

	var (
		bmSignals  []string
		cdnSignals []string
	)

	abck, hasAbck := hasCookie(resp.Cookies, "_abck")
	if hasAbck {
		bmSignals = append(bmSignals, "cookie:_abck="+short(abck, 20))
	}
	if _, ok := hasCookie(resp.Cookies, "ak_bmsc"); ok {
		bmSignals = append(bmSignals, "cookie:ak_bmsc")
	}
	if _, ok := hasCookie(resp.Cookies, "bm_sz"); ok {
		bmSignals = append(bmSignals, "cookie:bm_sz")
	}
	if _, ok := hasCookie(resp.Cookies, "bm_sv"); ok {
		bmSignals = append(bmSignals, "cookie:bm_sv")
	}
	if _, ok := hasCookie(resp.Cookies, "bm_mi"); ok {
		bmSignals = append(bmSignals, "cookie:bm_mi")
	}
	if _, ok := hasCookie(resp.Cookies, "_bman"); ok {
		// _bman: BMP-Premier session cookie (travel/hospitality sites).
		bmSignals = append(bmSignals, "cookie:_bman")
	}
	if resp.bodyHas("reference #") && resp.bodyHas("akamai") {
		bmSignals = append(bmSignals, "body:akamai-reference-id")
	}
	if resp.bodyHas("sensor_data") {
		bmSignals = append(bmSignals, "body:sensor_data")
	}

	if server, ok := hasHeader(resp.Header, "Server"); ok &&
		(hasPrefixFold(server, "AkamaiGHost") || hasPrefixFold(server, "AkamaiNetStorage")) {
		cdnSignals = append(cdnSignals, "header:server="+server)
	}
	for name := range resp.Header {
		if hasPrefixFold(name, "X-Akamai-") {
			cdnSignals = append(cdnSignals, "header:"+name)
			break
		}
	}

	if len(bmSignals) == 0 && len(cdnSignals) == 0 {
		return nil
	}

	// CDN only, not bot-layer evidence.
	if len(bmSignals) == 0 {
		layer, blocked := statusLayer(resp)
		return &Detection{
			Vendor:     "akamai-cdn",
			Confidence: "low",
			Signals:    append([]string{"(cdn-only, not bot manager)"}, cdnSignals...),
			Layer:      layer,
			Blocked:    blocked,
		}
	}

	det := &Detection{
		Vendor:     "akamai",
		Confidence: "high",
		Signals:    append(bmSignals, cdnSignals...),
	}

	// non-block status with BM signals = sensor profiling, not a denial.
	profiling := abckIsSensor(abck) ||
		resp.bodyHas("sensor_data") ||
		containsSignal(bmSignals, "bm_sz") ||
		containsSignal(bmSignals, "ak_bmsc")
	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case resp.StatusCode == 403 || resp.StatusCode == 511:
		det.Layer = LayerHTTP
		det.Blocked = true
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	case profiling:
		det.Layer = LayerSensor
		det.Blocked = false
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}

	return det
}

func init() { Register(akamai{}) }

// abckIsSensor reports whether _abck's verdict field is -1 (still profiling).
func abckIsSensor(abck string) bool {
	parts := strings.Split(abck, "~")
	if len(parts) < 2 {
		return false
	}
	return parts[1] == "-1"
}

func containsSignal(signals []string, sub string) bool {
	for _, s := range signals {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
