package hunt

import (
	"fmt"
	"strings"

	"github.com/NotChaosuu/wafprobe/internal/client"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	tls "github.com/bogdanfinn/utls"
)

// CurlFor renders a curl invocation that reproduces what a mutation sends.
// TLS/ALPN map to curl flags, the rest to -H/-X/--data.
func CurlFor(target, method, baseUA, baseCookie string, body []byte, baseHeaders []persona.HeaderField, m Mutation) string {
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
	case opts.MinTLSVersion == tls.VersionTLS12 && opts.MaxTLSVersion == tls.VersionTLS12:
		lines = append(lines, "  --tlsv1.2 --tls-max 1.2")
	case opts.MinTLSVersion == tls.VersionTLS13 && opts.MaxTLSVersion == tls.VersionTLS13:
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

	// merge base+mutation headers keeping wire order, then drop
	var merged []persona.HeaderField
	pos := map[string]int{}
	addKV := func(name, value string) {
		key := strings.ToLower(name)
		if i, ok := pos[key]; ok {
			merged[i].Value = value
			return
		}
		pos[key] = len(merged)
		merged = append(merged, persona.HeaderField{Name: name, Value: value})
	}
	for _, h := range baseHeaders {
		addKV(h.Name, h.Value)
	}
	for _, h := range opts.ExtraHeaders {
		addKV(h.Name, h.Value)
	}
	dropped := map[string]bool{}
	for _, d := range opts.DropHeaders {
		dropped[strings.ToLower(d)] = true
	}
	for _, h := range merged {
		if dropped[strings.ToLower(h.Name)] {
			continue
		}
		lines = append(lines, fmt.Sprintf("  -H %s", quote(h.Name+": "+h.Value)))
	}

	if len(body) > 0 {
		lines = append(lines, fmt.Sprintf("  --data %s", quote(string(body))))
	}

	// always quote URLs; '&' is a command separator in cmd.exe
	lines = append(lines, fmt.Sprintf("  %s", forceQuote(target)))

	return strings.Join(lines, " \\\n")
}

// quote single-quotes args with POSIX or cmd.exe metacharacters.
func quote(s string) string {
	if !strings.ContainsAny(s, " \t\n'\"\\$`&?*=()|<>;{}[]") && len(s) > 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func forceQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
