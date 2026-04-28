package detect

// DataDome detector.
//
// Signals:
//   - `datadome` cookie set (high confidence)
//   - `x-datadome` / `x-dd-b` response headers
//   - `Server: DataDome` response header
//   - 403 + DataDome captcha page body
//
// Block semantics:
//   - 403 with datadome cookie → block
//   - 403 + "geo.captcha-delivery.com" → challenge (interstitial)
//   - 200 + datadome cookie → pass with tracking

type datadome struct{}

func (datadome) Vendor() string { return "datadome" }

func (datadome) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

	if _, ok := hasCookie(resp.Cookies, "datadome"); ok {
		signals = append(signals, "cookie:datadome")
	}
	if _, ok := hasHeader(resp.Header, "X-DataDome"); ok {
		signals = append(signals, "header:x-datadome")
	}
	if v, ok := hasHeader(resp.Header, "X-DataDome-CID"); ok {
		signals = append(signals, "header:x-datadome-cid="+short(v, 16))
	}
	if server, ok := hasHeader(resp.Header, "Server"); ok && hasPrefixFold(server, "DataDome") {
		signals = append(signals, "header:server=DataDome")
	}
	if bodyContains(resp.Body, "geo.captcha-delivery.com") ||
		bodyContains(resp.Body, "dd-captcha") ||
		(bodyContains(resp.Body, "datadome") && bodyContains(resp.Body, "captcha")) {
		signals = append(signals, "body:datadome-captcha")
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "datadome",
		Confidence: "high",
		Signals:    signals,
	}

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case bodyContains(resp.Body, "geo.captcha-delivery.com") || bodyContains(resp.Body, "dd-captcha"):
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

func init() { Register(datadome{}) }
