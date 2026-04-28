package detect

// AWS WAF detector.
//
// AWS WAF is harder to fingerprint than CDN-based WAFs because the HTTP
// response is crafted by the origin's WAF rules, not by a universal
// interstitial. Practical signals:
//   - `x-amzn-waf-*` / `x-amzn-errortype: WAFBlockException` headers
//   - default AWS WAF 403 block-page body: "Request blocked." with "AWS WAF"
//   - CloudFront `x-amz-cf-id` + 403 can imply WAF-at-CloudFront
//
// NOTE: AWS WAF is "mid-tier" per bug-bounty conventional wisdom; we keep
// confidence medium unless a vendor-specific header is present.

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
	if bodyContains(resp.Body, "aws waf") && bodyContains(resp.Body, "request blocked") {
		signals = append(signals, "body:aws-waf-block")
		confidence = "high"
	}
	if v, ok := hasHeader(resp.Header, "X-Amz-Cf-Id"); ok && resp.StatusCode == 403 {
		signals = append(signals, "header:x-amz-cf-id="+short(v, 20))
		// cloudfront returns 403 for lots of reasons — keep low confidence.
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
