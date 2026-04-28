package hunt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NotChaosuu/wafprobe/internal/client"
	utls "github.com/refraction-networking/utls"
)

// CurlFor renders a curl invocation that reproduces what a mutation sends.
// Best-effort: TLS-version mutations map to --tlsv1.2/--tlsv1.3, ALPN to
// --http1.1/--http2, the rest are -H/-X/--data flags.
func CurlFor(target, method, baseUA, baseCookie string, body []byte, baseHeaders map[string]string, m Mutation) string {
	opts := client.Options{}
	m.Apply(&opts)

	httpMethod := method
	if opts.MethodOverride != "" {
		httpMethod = opts.MethodOverride
	}
	if httpMethod == "" {
		httpMethod = "GET"
	}

	// UA precedence: mutation override > caller-set base > nothing.
	ua := baseUA
	if opts.UserAgentOverride != "" {
		ua = opts.UserAgentOverride
	}

	var lines []string
	lines = append(lines, "curl")

	switch {
	case opts.MinTLSVersion == utls.VersionTLS12 && opts.MaxTLSVersion == utls.VersionTLS12:
		lines = append(lines, "  --tlsv1.2 --tls-max 1.2")
	case opts.MinTLSVersion == utls.VersionTLS13 && opts.MaxTLSVersion == utls.VersionTLS13:
		lines = append(lines, "  --tlsv1.3 --tls-max 1.3")
	}

	if opts.ALPNOverride != nil {
		switch {
		case len(opts.ALPNOverride) == 1 && opts.ALPNOverride[0] == "http/1.1":
			lines = append(lines, "  --http1.1")
		case len(opts.ALPNOverride) == 1 && opts.ALPNOverride[0] == "h2":
			lines = append(lines, "  --http2")
		}
	}

	if httpMethod != "GET" {
		lines = append(lines, fmt.Sprintf("  -X %s", httpMethod))
	}

	if ua != "" {
		lines = append(lines, fmt.Sprintf("  -H %s", quote("User-Agent: "+ua)))
	}

	if baseCookie != "" && !opts.StripCookies {
		lines = append(lines, fmt.Sprintf("  -H %s", quote("Cookie: "+baseCookie)))
	}

	merged := map[string]string{}
	for k, v := range baseHeaders {
		merged[k] = v
	}
	for k, v := range opts.ExtraHeaders {
		merged[k] = v
	}
	for _, h := range opts.DropHeaders {
		for k := range merged {
			if strings.EqualFold(k, h) {
				delete(merged, k)
			}
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("  -H %s", quote(k+": "+merged[k])))
	}

	if len(body) > 0 {
		lines = append(lines, fmt.Sprintf("  --data %s", quote(string(body))))
	}

	// Always force-quote URLs — '&', '?', '=' are special in bash AND cmd.exe
	// (where '&' is the command separator).
	lines = append(lines, fmt.Sprintf("  %s", forceQuote(target)))

	return strings.Join(lines, " \\\n")
}

// quote single-quotes a shell argument that contains POSIX or cmd.exe
// metacharacters. cmd.exe needs '&' '?' '*' '(' ')' '|' '<' '>' ';' in here.
func quote(s string) string {
	if !strings.ContainsAny(s, " \t\n'\"\\$`&?*=()|<>;{}[]") && len(s) > 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// forceQuote always wraps in single-quotes.
func forceQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
