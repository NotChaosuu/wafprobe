package detect

import "strings"

// Cloudflare detector. Identification is keyed on cf-ray, cf-mitigated,
// and the __cf_bm / cf_clearance cookies (all vendor-specific).
//
// We label CF's two distinct bot mechanisms separately:
//
//   - Managed Challenge (legacy IUAM, cf_clearance interstitial): 403/503
//     with "Just a moment..." body. On success the browser gets a
//     cf_clearance cookie. Signal: body:managed-challenge.
//
//   - Turnstile widget (form captcha): 200 OK, page loads; the origin
//     embeds challenges.cloudflare.com/turnstile JS to gate form submits.
//     Not a block on the GET — but the page's forms are gated.
//     Signal: body:turnstile-widget.

type cloudflare struct{}

func (cloudflare) Vendor() string { return "cloudflare" }

func (cloudflare) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

	// Vendor identification.
	if v, ok := hasHeader(resp.Header, "CF-Ray"); ok {
		signals = append(signals, "header:cf-ray="+short(v, 24))
	}
	if v, ok := hasHeader(resp.Header, "CF-Mitigated"); ok {
		signals = append(signals, "header:cf-mitigated="+v)
	}
	if server, ok := hasHeader(resp.Header, "Server"); ok && hasPrefixFold(server, "cloudflare") {
		signals = append(signals, "header:server=cloudflare")
	}
	if _, ok := hasCookie(resp.Cookies, "__cf_bm"); ok {
		signals = append(signals, "cookie:__cf_bm")
	}
	if _, ok := hasCookie(resp.Cookies, "cf_clearance"); ok {
		signals = append(signals, "cookie:cf_clearance")
	}

	// Managed Challenge interstitial.
	isManagedChallenge := bodyContains(resp.Body, "cloudflare") &&
		(bodyContains(resp.Body, "attention required") ||
			bodyContains(resp.Body, "checking your browser") ||
			bodyContains(resp.Body, "please enable cookies") ||
			bodyContains(resp.Body, "just a moment") ||
			bodyContains(resp.Body, "ray id"))
	if isManagedChallenge {
		signals = append(signals, "body:managed-challenge")
	}

	// Turnstile widget embedded for form-submit gating.
	hasTurnstileWidget := bodyContains(resp.Body, "challenges.cloudflare.com/turnstile") ||
		bodyContains(resp.Body, `class="cf-turnstile"`) ||
		bodyContains(resp.Body, "cf-turnstile-")
	if hasTurnstileWidget {
		signals = append(signals, "body:turnstile-widget")
	}

	if len(signals) == 0 {
		return nil
	}

	det := &Detection{
		Vendor:     "cloudflare",
		Confidence: "high",
		Signals:    signals,
	}

	mitigated, _ := hasHeader(resp.Header, "CF-Mitigated")

	switch {
	case resp.StatusCode == 429:
		det.Layer = LayerRateLimit
		det.Blocked = true
	case mitigated == "challenge" || resp.StatusCode == 503 || isManagedChallenge:
		det.Layer = LayerChallenge
		det.Blocked = true
	case resp.StatusCode == 403:
		det.Layer = LayerHTTP
		det.Blocked = true
	case resp.StatusCode >= 500:
		det.Layer = LayerHTTP
		det.Blocked = true
	case hasTurnstileWidget && resp.StatusCode == 200:
		// Page loads, but its forms are gated by Turnstile.
		det.Layer = LayerSensor
		det.Blocked = false
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}
	return det
}

func init() { Register(cloudflare{}) }

// Helpers shared across detectors.

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}
