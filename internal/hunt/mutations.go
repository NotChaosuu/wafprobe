package hunt

import (
	"github.com/NotChaosuu/wafprobe/internal/client"
	tls "github.com/bogdanfinn/utls"
)

// Mutation is a single-axis change to client.Options.
type Mutation struct {
	Name  string
	Axis  string
	Apply func(*client.Options)
}

// AllMutations returns the base mutation set in execution order: TLS first,
// then ALPN/SNI, then HTTP-layer headers/cookies/method last.
func AllMutations() []Mutation {
	return []Mutation{
		// TLS version
		{
			Name: "force TLS 1.2",
			Axis: "tls-version",
			Apply: func(o *client.Options) {
				o.MinTLSVersion = tls.VersionTLS12
				o.MaxTLSVersion = tls.VersionTLS12
			},
		},
		{
			Name: "force TLS 1.3",
			Axis: "tls-version",
			Apply: func(o *client.Options) {
				o.MinTLSVersion = tls.VersionTLS13
				o.MaxTLSVersion = tls.VersionTLS13
			},
		},

		// ALPN
		{
			Name: "ALPN: http/1.1 only",
			Axis: "alpn",
			Apply: func(o *client.Options) {
				o.ALPNOverride = []string{"http/1.1"}
			},
		},
		{
			Name: "ALPN: h2 only",
			Axis: "alpn",
			Apply: func(o *client.Options) {
				o.ALPNOverride = []string{"h2"}
			},
		},
		{
			Name: "ALPN: empty list",
			Axis: "alpn",
			Apply: func(o *client.Options) {
				o.ALPNOverride = []string{}
			},
		},

		// SNI
		{
			Name: "SNI: omit",
			Axis: "sni",
			Apply: func(o *client.Options) {
				o.SNIOverride = "-"
			},
		},

		// User-Agent
		{
			Name: "UA: curl/8.0",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "curl/8.0"
			},
		},
		{
			Name: "UA: Googlebot",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
			},
		},
		{
			Name: "UA: empty",
			Axis: "user-agent",
			// http.Request requires a non-empty value to suppress the default
			// "Go-http-client/1.1"; a single space is the closest we get.
			Apply: func(o *client.Options) { o.UserAgentOverride = " " },
		},
		{
			Name: "UA: old IE 6",
			Axis: "user-agent",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
			},
		},

		// Cookies
		{
			Name: "drop all cookies",
			Axis: "cookies",
			Apply: func(o *client.Options) {
				o.StripCookies = true
			},
		},

		// Headers: add suspicious
		{
			Name: "add X-Forwarded-For: 127.0.0.1",
			Axis: "headers",
			Apply: func(o *client.Options) {
				addHdr(o, "X-Forwarded-For", "127.0.0.1")
			},
		},
		{
			Name: "add X-Real-IP: 127.0.0.1",
			Axis: "headers",
			Apply: func(o *client.Options) {
				addHdr(o, "X-Real-IP", "127.0.0.1")
			},
		},
		{
			Name: "add Referer: google.com",
			Axis: "headers",
			Apply: func(o *client.Options) {
				addHdr(o, "Referer", "https://www.google.com/")
			},
		},
		{
			Name: "add Accept-Language: en-US",
			Axis: "headers",
			Apply: func(o *client.Options) {
				addHdr(o, "Accept-Language", "en-US,en;q=0.9")
			},
		},

		// Headers: drop common
		{
			Name: "drop Accept-Encoding",
			Axis: "headers",
			Apply: func(o *client.Options) {
				o.DropHeaders = append(o.DropHeaders, "Accept-Encoding")
			},
		},
		{
			Name: "drop Accept",
			Axis: "headers",
			Apply: func(o *client.Options) {
				o.DropHeaders = append(o.DropHeaders, "Accept")
			},
		},

		// Method
		{
			Name: "method: HEAD",
			Axis: "method",
			Apply: func(o *client.Options) {
				o.MethodOverride = "HEAD"
			},
		},
		{
			Name: "method: OPTIONS",
			Axis: "method",
			Apply: func(o *client.Options) {
				o.MethodOverride = "OPTIONS"
			},
		},

		// Combos
		{
			Name: "TLS 1.2 + ALPN http/1.1",
			Axis: "combo",
			Apply: func(o *client.Options) {
				o.MinTLSVersion = tls.VersionTLS12
				o.MaxTLSVersion = tls.VersionTLS12
				o.ALPNOverride = []string{"http/1.1"}
			},
		},
		{
			Name: "Googlebot UA + no cookies",
			Axis: "combo",
			Apply: func(o *client.Options) {
				o.UserAgentOverride = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
				o.StripCookies = true
			},
		},
	}
}
