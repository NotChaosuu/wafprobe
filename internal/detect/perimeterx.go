package detect

// PerimeterX / HUMAN Security detector.
//
// Signals:
//   - `_px` / `_pxvid` / `_pxhd` cookies (high confidence)
//   - `px-*` / `server: perimeterx` headers (rare but possible on enterprise)
//   - block page body referring to "Please verify you are a human"
//
// Block semantics:
//   - 403 with _px cookie → blocked
//   - 403 + "perimeterx" in body → challenge

type perimeterx struct{}

func (perimeterx) Vendor() string { return "perimeterx" }

func (perimeterx) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

	for _, c := range []string{"_px", "_pxvid", "_pxhd", "_pxde", "_pxCaptcha"} {
		if _, ok := hasCookie(resp.Cookies, c); ok {
			signals = append(signals, "cookie:"+c)
		}
	}
	if server, ok := hasHeader(resp.Header, "Server"); ok && hasPrefixFold(server, "PerimeterX") {
		signals = append(signals, "header:server=perimeterx")
	}
	if v, ok := hasHeader(resp.Header, "X-Px-Block"); ok {
		signals = append(signals, "header:x-px-block="+short(v, 16))
	}
	if bodyContains(resp.Body, "please verify you are a human") ||
		bodyContains(resp.Body, "perimeterx") ||
		bodyContains(resp.Body, "_pxcaptcha") {
		signals = append(signals, "body:perimeterx-challenge")
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "perimeterx",
		Confidence: "high",
		Signals:    signals,
	}

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case bodyContains(resp.Body, "please verify you are a human") ||
		bodyContains(resp.Body, "_pxcaptcha"):
		det.Layer = LayerChallenge
		det.Blocked = true
	case resp.StatusCode == 403:
		det.Layer = LayerHTTP
		det.Blocked = true
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}

	return det
}

func init() { Register(perimeterx{}) }
