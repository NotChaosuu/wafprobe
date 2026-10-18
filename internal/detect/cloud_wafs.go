package detect

type azureFrontDoor struct{}

func (azureFrontDoor) Vendor() string { return "azure-front-door" }

func (azureFrontDoor) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if _, ok := hasHeader(resp.Header, "X-Azure-Ref"); ok {
		signals = append(signals, "header:x-azure-ref")
	}
	blocked := false
	if resp.bodyHas("microsoft-azure-application-gateway/v2") {
		signals = append(signals, "body:app-gateway-block")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	name := "azure-front-door"
	if blocked {
		name = "azure-waf"
	}
	det := &Detection{Vendor: name, Confidence: "high", Signals: signals}
	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case blocked || resp.StatusCode == 403:
		det.Layer = LayerHTTP
		det.Blocked = true
	default:
		det.Layer = LayerPass
	}
	return det
}

type vercel struct{}

func (vercel) Vendor() string { return "vercel" }

func (vercel) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	challenge := false
	if v, ok := hasHeader(resp.Header, "X-Vercel-Mitigated"); ok {
		signals = append(signals, "header:x-vercel-mitigated="+v)
		if v == "challenge" {
			challenge = true
		}
	}
	if _, ok := hasHeader(resp.Header, "X-Vercel-Challenge-Token"); ok {
		signals = append(signals, "header:x-vercel-challenge-token")
		challenge = true
	}
	if resp.bodyHas("vercel security checkpoint") {
		signals = append(signals, "body:vercel-checkpoint")
		challenge = true
	}
	if len(signals) == 0 {
		return nil
	}
	det := &Detection{Vendor: "vercel", Confidence: "high", Signals: signals}
	if challenge {
		det.Layer = LayerChallenge
		det.Blocked = true
	} else {
		det.Layer = LayerPass
	}
	return det
}

type reblaze struct{}

func (reblaze) Vendor() string { return "reblaze" }

func (reblaze) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if s, ok := hasHeader(resp.Header, "Server"); ok && hasPrefixFold(s, "reblaze") {
		signals = append(signals, "header:server=reblaze")
	}
	if _, ok := hasCookie(resp.Cookies, "rbzid"); ok {
		signals = append(signals, "cookie:rbzid")
	}
	blocked := false
	if resp.bodyHas("current session has been terminated") && resp.bodyHas("access denied") {
		signals = append(signals, "body:reblaze-block")
		blocked = true
	}
	if len(signals) == 0 {
		return nil
	}
	return blockOr(resp, "reblaze", signals, blocked || resp.StatusCode == 403)
}

type queueit struct{}

func (queueit) Vendor() string { return "queue-it" }

func (queueit) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string
	if _, ok := hasHeader(resp.Header, "X-Qit-VisitorSessionId"); ok {
		signals = append(signals, "header:x-qit-visitorsessionid")
	}
	for _, c := range resp.Cookies {
		if c.Name == "Queue-it-visitorsession" || hasPrefixFold(c.Name, "QueueITAccepted") {
			signals = append(signals, "cookie:"+c.Name)
		}
	}
	waiting := false
	if loc, ok := hasHeader(resp.Header, "Location"); ok && bodyContains([]byte(loc), "queue-it.net") {
		signals = append(signals, "redirect:queue-it.net")
		waiting = true
	}
	if resp.bodyHas("queue-it.net") || resp.bodyHas("queueittoken") {
		signals = append(signals, "body:queue-it")
		waiting = true
	}
	if len(signals) == 0 {
		return nil
	}
	det := &Detection{Vendor: "queue-it", Confidence: "high", Signals: signals}
	if waiting {
		det.Layer = LayerChallenge
		det.Blocked = true
	} else {
		det.Layer = LayerPass
	}
	return det
}

func init() {
	Register(azureFrontDoor{})
	Register(vercel{})
	Register(reblaze{})
	Register(queueit{})
}
