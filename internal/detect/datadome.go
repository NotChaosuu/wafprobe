package detect

// DataDome detector. geo.captcha-delivery.com on a 403 is the captcha interstitial.

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
	if resp.bodyHas("geo.captcha-delivery.com") ||
		resp.bodyHas("dd-captcha") ||
		(resp.bodyHas("datadome") && resp.bodyHas("captcha")) {
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
	case resp.bodyHas("geo.captcha-delivery.com") || resp.bodyHas("dd-captcha"):
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
