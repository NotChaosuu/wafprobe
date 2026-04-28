package detect

// Akamai detector.
//
// Akamai is both a CDN and a bot manager (Akamai Bot Manager / BMP). Many
// sites use the CDN with a different bot vendor in front (Kasada, Shape,
// etc), so we have to separate the two:
//
//   - HIGH "akamai" — bot manager signals (_abck / ak_bmsc / bm_sz / _bman /
//     bm_sv / bm_mi cookies, "sensor_data" in body)
//   - LOW  "akamai-cdn" — only CDN signals (Server: AkamaiGHost,
//     X-Akamai-* headers). The CDN classification by itself does NOT mean
//     bot protection is active.
//
// _abck values encode BMP state in pipe-delimited fields:
//   ||0||  still profiling          → LayerSensor, not blocked
//   ||1||  flagged                  → LayerHTTP,   blocked
//   ||2||  flagged + verified bot   → LayerHTTP,   blocked

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

	// Bot Manager signals
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
		// _bman is BMP-Premier's session cookie (seen on hospitality / travel).
		bmSignals = append(bmSignals, "cookie:_bman")
	}
	if bodyContains(resp.Body, "reference #") && bodyContains(resp.Body, "akamai") {
		bmSignals = append(bmSignals, "body:akamai-reference-id")
	}
	if bodyContains(resp.Body, "sensor_data") {
		bmSignals = append(bmSignals, "body:sensor_data")
	}

	// CDN-level signals — present on Akamai-fronted traffic regardless of BMP.
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

	// CDN signals only — report as "akamai-cdn" so the user knows this is
	// not bot-layer evidence.
	if len(bmSignals) == 0 {
		return &Detection{
			Vendor:     "akamai-cdn",
			Confidence: "low",
			Signals:    append([]string{"(cdn-only, not bot manager)"}, cdnSignals...),
			Layer:      layerFromStatus(resp.StatusCode),
			Blocked:    resp.StatusCode >= 400,
		}
	}

	det := &Detection{
		Vendor:     "akamai",
		Confidence: "high",
		Signals:    append(bmSignals, cdnSignals...),
	}

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case resp.StatusCode == 403 || resp.StatusCode == 511:
		det.Layer = LayerHTTP
		det.Blocked = true
	case bodyContains(resp.Body, "sensor_data"):
		det.Layer = LayerChallenge
		det.Blocked = true
	case abckIsBlocking(abck):
		det.Layer = LayerHTTP
		det.Blocked = true
	case abckIsSensor(abck):
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

func init() { Register(akamai{}) }

func abckIsBlocking(abck string) bool {
	if abck == "" {
		return false
	}
	return contains(abck, "||1||") || contains(abck, "||2||")
}

func abckIsSensor(abck string) bool {
	if abck == "" {
		return false
	}
	return contains(abck, "||0||")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
