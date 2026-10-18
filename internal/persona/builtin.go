package persona

import (
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Each UA matches the major version of its tls-client profile, so the UA and
// the ClientHello agree. Safari 16 is the newest desktop preset tls-client ships.
func init() {
	const (
		uaChrome152 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
		uaChrome133 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
		uaChrome131 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
		uaFirefox   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
		uaSafari    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
		uaIOS       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
	)

	register(Persona{
		ID:         "chrome-latest",
		Name:       "Chrome (latest preset)",
		UserAgent:  uaChrome152,
		Profile:    profiles.Chrome_152,
		Headers:    chromeHeaders(uaChrome152, "152", "Windows"),
		Randomized: true,
	})

	register(Persona{
		ID:         "chrome-133",
		Name:       "Chrome 133",
		UserAgent:  uaChrome133,
		Profile:    profiles.Chrome_133,
		Headers:    chromeHeaders(uaChrome133, "133", "Windows"),
		Randomized: true,
	})

	register(Persona{
		ID:         "chrome-131",
		Name:       "Chrome 131",
		UserAgent:  uaChrome131,
		Profile:    profiles.Chrome_131,
		Headers:    chromeHeaders(uaChrome131, "131", "Windows"),
		Randomized: true,
	})

	register(Persona{
		ID:        "firefox-latest",
		Name:      "Firefox 148",
		UserAgent: uaFirefox,
		Profile:   profiles.Firefox_148,
		Headers:   firefoxHeaders(uaFirefox),
	})

	register(Persona{
		ID:        "safari-16",
		Name:      "Safari 16 (macOS)",
		UserAgent: uaSafari,
		Profile:   profiles.Safari_16_0,
		Headers:   safariHeaders(uaSafari),
	})

	register(Persona{
		ID:        "ios-17",
		Name:      "iOS 17 Safari",
		UserAgent: uaIOS,
		Profile:   profiles.Safari_IOS_17_0,
		Headers:   safariHeaders(uaIOS),
	})

	// naked scripts: Go's HelloGolang and Go's h2 SETTINGS, for contrast.
	register(Persona{
		ID:        "go-stdlib",
		Name:      "Go net/http (stock)",
		UserAgent: "Go-http-client/1.1",
		Profile:   stockProfile(),
		Headers:   []HeaderField{{"user-agent", "Go-http-client/1.1"}, {"accept-encoding", "gzip"}},
		Stock:     true,
	})

	register(Persona{
		ID:        "python-requests",
		Name:      "Python requests (stock)",
		UserAgent: "python-requests/2.32.3",
		Profile:   stockProfile(),
		Headers:   []HeaderField{{"user-agent", "python-requests/2.32.3"}, {"accept-encoding", "gzip, deflate"}, {"accept", "*/*"}, {"connection", "keep-alive"}},
		Stock:     true,
	})
}

// stockProfile mimics a stdlib Go client: HelloGolang plus http2.Transport's
// SETTINGS, window and pseudo-header order (a,m,p,s).
func stockProfile() profiles.ClientProfile {
	settings := map[http2.SettingID]uint32{
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 4194304,
		http2.SettingMaxFrameSize:      16384,
		http2.SettingMaxHeaderListSize: 10485760,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	}
	pseudoOrder := []string{":authority", ":method", ":path", ":scheme"}
	return profiles.NewClientProfile(
		tls.HelloGolang,
		settings, settingsOrder, pseudoOrder,
		1073741824, // connection-window update, Go's value
		nil, nil, 0, false,
		nil, nil, 0, nil, false,
	)
}

// chromeHeaders is Chromium's navigation header order; UA goes after
// upgrade-insecure-requests.
func chromeHeaders(ua, major, platform string) []HeaderField {
	return []HeaderField{
		{"sec-ch-ua", `"Chromium";v="` + major + `", "Google Chrome";v="` + major + `", "Not?A_Brand";v="24"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"` + platform + `"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", ua},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	}
}

func firefoxHeaders(ua string) []HeaderField {
	return []HeaderField{
		{"user-agent", ua},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.5"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"priority", "u=0, i"},
		{"te", "trailers"},
	}
}

func safariHeaders(ua string) []HeaderField {
	return []HeaderField{
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"user-agent", ua},
		{"accept-language", "en-US,en;q=0.9"},
		{"sec-fetch-mode", "navigate"},
		{"accept-encoding", "gzip, deflate, br"},
		{"sec-fetch-dest", "document"},
	}
}
