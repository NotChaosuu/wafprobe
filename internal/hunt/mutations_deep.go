package hunt

import (
	"github.com/NotChaosuu/wafprobe/internal/client"
)

// DeepMutations is the extended mutation set used by `hunt --deep`.
// Adds Sec-CH-UA client hints, Sec-Fetch-* metadata, origin-IP spoofing,
// 15+ more user agents, exotic methods, and combos.
func DeepMutations() []Mutation {
	return append(AllMutations(), deepExtras()...)
}

func deepExtras() []Mutation {
	return []Mutation{
		// Sec-CH-UA client hints — Chrome 90+ sends these, most bots don't
		{
			Name: "drop Sec-Ch-Ua hints",
			Axis: "client-hints",
			Apply: func(o *client.Options) {
				o.DropHeaders = append(o.DropHeaders, "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform")
			},
		},
		{
			Name: "fake Sec-Ch-Ua: Chrome 147",
			Axis: "client-hints",
			Apply: func(o *client.Options) {
				addHdr(o, "Sec-Ch-Ua", `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`)
				addHdr(o, "Sec-Ch-Ua-Mobile", "?0")
				addHdr(o, "Sec-Ch-Ua-Platform", `"Windows"`)
			},
		},
		{
			Name: "spoof Sec-Ch-Ua: Mobile",
			Axis: "client-hints",
			Apply: func(o *client.Options) {
				addHdr(o, "Sec-Ch-Ua", `"Google Chrome";v="147"`)
				addHdr(o, "Sec-Ch-Ua-Mobile", "?1")
				addHdr(o, "Sec-Ch-Ua-Platform", `"Android"`)
			},
		},

		// Sec-Fetch-* metadata — modern browsers always send these
		{
			Name: "add Sec-Fetch-* (real-browser shape)",
			Axis: "sec-fetch",
			Apply: func(o *client.Options) {
				addHdr(o, "Sec-Fetch-Site", "same-origin")
				addHdr(o, "Sec-Fetch-Mode", "cors")
				addHdr(o, "Sec-Fetch-Dest", "empty")
			},
		},
		{
			Name: "drop Sec-Fetch-*",
			Axis: "sec-fetch",
			Apply: func(o *client.Options) {
				o.DropHeaders = append(o.DropHeaders, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest")
			},
		},

		// Origin / forwarding-header spoofing
		{
			Name: "spoof True-Client-IP: 127.0.0.1",
			Axis: "origin-spoof",
			Apply: func(o *client.Options) { addHdr(o, "True-Client-IP", "127.0.0.1") },
		},
		{
			Name: "spoof CF-Connecting-IP: 127.0.0.1",
			Axis: "origin-spoof",
			Apply: func(o *client.Options) { addHdr(o, "CF-Connecting-IP", "127.0.0.1") },
		},
		{
			Name: "spoof X-Originating-IP",
			Axis: "origin-spoof",
			Apply: func(o *client.Options) { addHdr(o, "X-Originating-IP", "127.0.0.1") },
		},
		{
			Name: "spoof X-Forwarded-Host: localhost",
			Axis: "origin-spoof",
			Apply: func(o *client.Options) { addHdr(o, "X-Forwarded-Host", "localhost") },
		},
		{
			Name: "spoof X-Forwarded-Proto: http",
			Axis: "origin-spoof",
			Apply: func(o *client.Options) { addHdr(o, "X-Forwarded-Proto", "http") },
		},

		// Extended User-Agent set
		{
			Name: "UA: Bingbot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
			},
		},
		{
			Name: "UA: DuckDuckBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)"
			},
		},
		{
			Name: "UA: Applebot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)"
			},
		},
		{
			Name: "UA: archive.org_bot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)"
			},
		},
		{
			Name: "UA: Edge 131",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
			},
		},
		{
			Name: "UA: Mobile Chrome (Android)",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36"
			},
		},
		{
			Name: "UA: WhatsApp link preview",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "WhatsApp/2.23.20.0 A"
			},
		},
		{
			Name: "UA: Slackbot link unfurler",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
			},
		},
		{
			Name: "UA: facebookexternalhit",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
			},
		},
		{
			Name: "UA: Brave (looks like Chrome but isn't)",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Brave/1.78.0"
			},
		},
		{
			Name: "UA: Yandex Browser",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 YaBrowser/24.10.0.0 Safari/537.36"
			},
		},
		{
			Name: "UA: YandexBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
			},
		},
		{
			Name: "UA: Discordbot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
			},
		},
		{
			Name: "UA: TelegramBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "TelegramBot (like TwitterBot)"
			},
		},
		{
			Name: "UA: LinkedInBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/4.5 +http://www.linkedin.com)"
			},
		},
		{
			Name: "UA: Pinterest",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Pinterest/0.2 (+https://www.pinterest.com/bot.html)"
			},
		},
		{
			Name: "UA: Twitterbot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Twitterbot/1.0"
			},
		},
		{
			Name: "UA: Samsung Internet",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S921U) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/124.0.0.0 Mobile Safari/537.36"
			},
		},
		{
			Name: "UA: Opera",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/115.0.0.0"
			},
		},
		{
			Name: "UA: Vivaldi",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Vivaldi/6.9.3447.54"
			},
		},
		{
			Name: "UA: iPad Safari",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
			},
		},
		{
			Name: "UA: SemrushBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"
			},
		},
		{
			Name: "UA: AhrefsBot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
			},
		},

		// More headers
		{
			Name: "add DNT: 1",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "DNT", "1") },
		},
		{
			Name: "add Save-Data: on",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Save-Data", "on") },
		},
		{
			Name: "add Upgrade-Insecure-Requests: 1",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Upgrade-Insecure-Requests", "1") },
		},
		{
			Name: "add Priority: u=1, i (Chrome 124+)",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Priority", "u=1, i") },
		},
		{
			Name: "add Cache-Control: no-cache",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Cache-Control", "no-cache") },
		},
		{
			Name: "add Pragma: no-cache",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Pragma", "no-cache") },
		},
		{
			Name: "add Range: bytes=0-1023",
			Axis: "headers",
			Apply: func(o *client.Options) { addHdr(o, "Range", "bytes=0-1023") },
		},

		// More methods
		{
			Name: "method: PURGE",
			Axis: "method",
			Apply: func(o *client.Options) { o.MethodOverride = "PURGE" },
		},
		{
			Name: "method: TRACE",
			Axis: "method",
			Apply: func(o *client.Options) { o.MethodOverride = "TRACE" },
		},
		{
			Name: "method: lowercase get",
			Axis: "method",
			Apply: func(o *client.Options) { o.MethodOverride = "get" },
		},

		// Combos
		{
			Name: "FULL Chrome 147 client-hints kit",
			Axis: "combo",
			Apply: func(o *client.Options) {
				addHdr(o, "Sec-Ch-Ua", `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`)
				addHdr(o, "Sec-Ch-Ua-Mobile", "?0")
				addHdr(o, "Sec-Ch-Ua-Platform", `"Windows"`)
				addHdr(o, "Sec-Fetch-Site", "same-origin")
				addHdr(o, "Sec-Fetch-Mode", "cors")
				addHdr(o, "Sec-Fetch-Dest", "empty")
				addHdr(o, "Upgrade-Insecure-Requests", "1")
				addHdr(o, "Priority", "u=1, i")
			},
		},
		{
			Name: "Googlebot UA + spoof X-Forwarded-For: 66.249.66.1",
			Axis: "combo",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
				addHdr(o, "X-Forwarded-For", "66.249.66.1")
			},
		},
	}
}

func addHdr(o *client.Options, name, val string) {
	if o.ExtraHeaders == nil {
		o.ExtraHeaders = map[string]string{}
	}
	o.ExtraHeaders[name] = val
}
