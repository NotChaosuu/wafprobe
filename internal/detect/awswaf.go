package detect

// AWS WAF block pages come from the customer's rules, so there's no universal
// interstitial. Confidence stays medium unless an x-amzn-waf-* header shows up.

type awsWAF struct{}

func (awsWAF) Vendor() string { return "aws-waf" }

func (awsWAF) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var (
		signals    []string
		confidence = "medium"
	)

	if v, ok := hasHeader(resp.Header, "X-Amzn-ErrorType"); ok && hasPrefixFold(v, "WAF") {
		signals = append(signals, "header:x-amzn-errortype="+v)
		confidence = "high"
	}
	for name := range resp.Header {
		if hasPrefixFold(name, "X-Amzn-Waf-") {
			signals = append(signals, "header:"+name)
			confidence = "high"
		}
	}
	if resp.bodyHas("aws waf") && resp.bodyHas("request blocked") {
		signals = append(signals, "body:aws-waf-block")
		confidence = "high"
	}
	if v, ok := hasHeader(resp.Header, "X-Amz-Cf-Id"); ok && resp.StatusCode == 403 {
		signals = append(signals, "header:x-amz-cf-id="+short(v, 20))
		// cloudfront 403s for lots of reasons
		if confidence == "medium" {
			confidence = "low"
		}
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "aws-waf",
		Confidence: confidence,
		Signals:    signals,
	}

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
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

func init() { Register(awsWAF{}) }
