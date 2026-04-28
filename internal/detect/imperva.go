package detect

// Imperva (formerly Incapsula) detector.
//
// Signals:
//   - `x-iinfo`, `x-cdn: Incapsula` headers
//   - `incap_ses_*` and `visid_incap_*` cookies
//   - Imperva interstitial body: "Incapsula incident ID"

type imperva struct{}

func (imperva) Vendor() string { return "imperva" }

func (imperva) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

	if _, ok := hasHeader(resp.Header, "X-Iinfo"); ok {
		signals = append(signals, "header:x-iinfo")
	}
	if v, ok := hasHeader(resp.Header, "X-CDN"); ok && hasPrefixFold(v, "Incapsula") {
		signals = append(signals, "header:x-cdn=Incapsula")
	}
	for _, c := range resp.Cookies {
		if hasPrefixFold(c.Name, "incap_ses_") || hasPrefixFold(c.Name, "visid_incap_") {
			signals = append(signals, "cookie:"+c.Name)
			break
		}
	}
	if bodyContains(resp.Body, "incapsula incident id") {
		signals = append(signals, "body:incapsula-incident-id")
	}
	if bodyContains(resp.Body, "access denied") && bodyContains(resp.Body, "imperva") {
		signals = append(signals, "body:imperva-access-denied")
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "imperva",
		Confidence: "high",
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

func init() { Register(imperva{}) }
