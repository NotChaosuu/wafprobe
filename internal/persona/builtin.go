package persona

import utls "github.com/refraction-networking/utls"

// utls v1.8.2 ships presets up to Chrome 133 and Firefox 120; real Chrome
// is ~147 and Firefox ~148 in the wild. Chrome's ClientHello doesn't
// change every release (133 and 147 produce the same JA3), so we pair
// utls's newest preset with a current User-Agent. The drift is invisible
// to most WAFs which check JA3 and UA independently.
func init() {
	// chrome-latest is the default. HelloChrome_Auto + Chrome 147 UA.
	register(Persona{
		ID:          "chrome-latest",
		Name:        "Chrome (latest UA)",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
		ClientHello: utls.HelloChrome_Auto,
		Randomized:  true,
	})

	// chrome-133: TLS and UA versions matched. Pick this when you want a
	// deterministic profile with no drift.
	register(Persona{
		ID:          "chrome-133",
		Name:        "Chrome 133",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		ClientHello: utls.HelloChrome_133,
		Randomized:  true,
	})

	// chrome-131: older but still modern baseline for comparison probes.
	register(Persona{
		ID:          "chrome-131",
		Name:        "Chrome 131",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		ClientHello: utls.HelloChrome_131,
		Randomized:  true,
	})

	// firefox-latest: utls only ships Firefox 120 TLS preset; paired with
	// current Firefox 148 UA. Firefox's TLS stack changes rarely.
	register(Persona{
		ID:          "firefox-latest",
		Name:        "Firefox (latest UA)",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
		ClientHello: utls.HelloFirefox_120,
	})

	register(Persona{
		ID:          "safari-17",
		Name:        "Safari 17 (macOS)",
		UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		ClientHello: utls.HelloSafari_16_0,
	})

	register(Persona{
		ID:          "ios-17",
		Name:        "iOS 17 Safari",
		UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		ClientHello: utls.HelloIOS_14,
	})

	// go-stdlib: stock Go net/http TLS stack, no utls. Anchors the contrast
	// against the browser personas — most WAFs reject this fingerprint.
	register(Persona{
		ID:          "go-stdlib",
		Name:        "Go net/http (stock)",
		UserAgent:   "Go-http-client/1.1",
		UseStockTLS: true,
	})

	// python-requests: same TLS as go-stdlib (we run from Go), different UA —
	// useful for separating UA-based blocks from TLS-based blocks in reports.
	register(Persona{
		ID:          "python-requests",
		Name:        "Python requests (stock)",
		UserAgent:   "python-requests/2.31.0",
		UseStockTLS: true,
	})
}
