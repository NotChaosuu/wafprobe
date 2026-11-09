package detect

import (
	"net/http"
	"strings"
)

// AWS WAF block pages come from the customer's rules, so there's no universal
// interstitial. Confidence stays medium unless an x-amzn-waf-* header or the
// aws-waf-token cookie shows up.
//
// Block defaults to 403, but CAPTCHA and Challenge don't: AWS answers a
// Challenge with 202 and a CAPTCHA with 405, and says which one in
// x-amzn-waf-action. Going by status alone, both read as a pass.

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
			sig := "header:" + name
			if strings.EqualFold(name, "X-Amzn-Waf-Action") {
				sig = "header:x-amzn-waf-action=" + short(resp.Header.Get(name), 16)
			}
			signals = append(signals, sig)
			confidence = "high"
		}
	}
	// set once a client has passed a Challenge or CAPTCHA
	if _, ok := hasCookie(resp.Cookies, "aws-waf-token"); ok {
		signals = append(signals, "cookie:aws-waf-token")
		confidence = "high"
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

	if layer, ok := awsWAFAction(resp.Header); ok {
		det.Layer = layer
		det.Blocked = true
		return det
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

// awsWAFAction reads x-amzn-waf-action. Both values put an interstitial in
// front of the page, and wafprobe has no separate CAPTCHA layer, so both map
// to the challenge layer.
func awsWAFAction(h http.Header) (Layer, bool) {
	v, ok := hasHeader(h, "X-Amzn-Waf-Action")
	if !ok {
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "challenge", "captcha":
		return LayerChallenge, true
	}
	return "", false
}

func init() { Register(awsWAF{}) }
