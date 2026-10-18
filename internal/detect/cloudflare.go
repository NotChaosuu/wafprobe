package detect

import "strings"

// Cloudflare detector. Managed Challenge ("Just a moment...", 403/503) is a
// block; a Turnstile widget on a 200 only gates the page's forms.

type cloudflare struct{}

func (cloudflare) Vendor() string { return "cloudflare" }

func (cloudflare) Detect(resp *Response) *Detection {
	if resp == nil {
		return nil
	}
	var signals []string

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

	isManagedChallenge := resp.bodyHas("cloudflare") &&
		(resp.bodyHas("attention required") ||
			resp.bodyHas("checking your browser") ||
			resp.bodyHas("please enable cookies") ||
			resp.bodyHas("just a moment") ||
			resp.bodyHas("ray id"))
	if isManagedChallenge {
		signals = append(signals, "body:managed-challenge")
	}

	hasTurnstileWidget := resp.bodyHas("challenges.cloudflare.com/turnstile") ||
		resp.bodyHas(`class="cf-turnstile"`) ||
		resp.bodyHas("cf-turnstile-")
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
		det.Layer = LayerSensor
		det.Blocked = false
	default:
		det.Layer = LayerPass
		det.Blocked = false
	}
	return det
}

func init() { Register(cloudflare{}) }

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
