package detect

type widget struct {
	vendor  string
	markers []string
}

func (w widget) Vendor() string { return w.vendor }

func (w widget) Detect(resp *Response) *Detection {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	var signals []string
	for _, m := range w.markers {
		if resp.bodyHas(m) {
			signals = append(signals, "body:"+m)
		}
	}
	if len(signals) == 0 {
		return nil
	}
	layer, blocked := widgetOutcome(resp)
	return &Detection{
		Vendor:     w.vendor,
		Confidence: "high",
		Signals:    signals,
		Layer:      layer,
		Blocked:    blocked,
	}
}

// widgetOutcome: a captcha on a 403/429/5xx page is a block, on a 2xx it's a sensor.
func widgetOutcome(resp *Response) (Layer, bool) {
	if layer, blocked := statusLayer(resp); blocked {
		return layer, true
	}
	return LayerSensor, false
}

func init() {
	Register(widget{"arkose-labs", []string{"arkoselabs.com", "funcaptcha"}})
	Register(widget{"hcaptcha", []string{"js.hcaptcha.com", "h-captcha"}})
	Register(recaptcha{})
	Register(widget{"friendly-captcha", []string{"frc-captcha", "friendlycaptcha.com"}})
}

type recaptcha struct{}

func (recaptcha) Vendor() string { return "recaptcha" }

func (recaptcha) Detect(resp *Response) *Detection {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	var signals []string
	enterprise := false
	if resp.bodyHas("recaptcha/enterprise.js") || resp.bodyHas("grecaptcha.enterprise") {
		signals = append(signals, "body:recaptcha-enterprise")
		enterprise = true
	}
	if len(signals) == 0 && (resp.bodyHas("google.com/recaptcha") ||
		resp.bodyHas("recaptcha.net/recaptcha") || resp.bodyHas("g-recaptcha")) {
		signals = append(signals, "body:recaptcha")
	}
	if len(signals) == 0 {
		return nil
	}
	vendor := "recaptcha"
	if enterprise {
		vendor = "recaptcha-enterprise"
	}
	layer, blocked := widgetOutcome(resp)
	return &Detection{Vendor: vendor, Confidence: "high", Signals: signals, Layer: layer, Blocked: blocked}
}
