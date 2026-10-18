package detect

// Kasada detector. Clients must echo x-kpsdk-ct/x-kpsdk-cd; we can only see
// the header names referenced, not make valid values. 429 is Kasada's normal
// block status, so it maps to LayerHTTP, not LayerRateLimit.

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
	if resp.bodyHas("/ips.js") {
		signals = append(signals, "body:kasada-ips.js")
	}
	if resp.bodyHas("kpsdk") || resp.bodyHas("kasada") {
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
		det.Layer = LayerHTTP
		det.Blocked = true
	default:
		if layer, blocked := statusLayer(resp); blocked {
			det.Layer = layer
			det.Blocked = true
		} else {
			// sensor on a passing page. Vercel BotID serves it from /a3/p.js, not /ips.js.
			det.Layer = LayerSensor
			det.Blocked = false
		}
	}

	return det
}

func init() { Register(kasada{}) }
