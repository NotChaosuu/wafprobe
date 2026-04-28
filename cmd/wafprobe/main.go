// Command wafprobe is a CLI for probing WAF/bot-management at a target URL.
// See `wafprobe -h` for subcommands.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/NotChaosuu/wafprobe/internal/client"
	"github.com/NotChaosuu/wafprobe/internal/harimport"
	"github.com/NotChaosuu/wafprobe/internal/hunt"
	"github.com/NotChaosuu/wafprobe/internal/output"
	"github.com/NotChaosuu/wafprobe/internal/persona"
	"github.com/NotChaosuu/wafprobe/internal/probe"
)

// Version is overridable at build time: -ldflags "-X main.Version=x.y.z".
var Version = "0.3.0"

const topUsage = `wafprobe — probe a target's WAF stack.

Usage:
  wafprobe <subcommand> [flags] <target-url>

Subcommands:
  probe       run multiple TLS personas against the target and classify each response
  hunt        surgically mutate one axis per probe to reverse-engineer what the WAF checks
  import-har  parse a Chrome / Firefox DevTools HAR export, extract the request shape, write a captured persona JSON
  list        list built-in personas
  version     print version

Global examples:
  wafprobe probe https://example.com
  wafprobe hunt --deep https://example.com
  wafprobe import-har devtools.har --filter "auth/login" -o captured.json
  wafprobe hunt --persona-file captured.json https://api.target.com/auth/login
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, topUsage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "probe":
		runProbe(os.Args[2:])
	case "hunt":
		runHunt(os.Args[2:])
	case "import-har":
		runImportHAR(os.Args[2:])
	case "list":
		runList()
	case "version", "--version", "-v":
		fmt.Println("wafprobe", Version)
	case "help", "--help", "-h":
		fmt.Print(topUsage)
	default:
		// Backwards compat: if the first arg looks like a URL or a flag,
		// treat the whole remainder as `probe` args.
		first := os.Args[1]
		if strings.HasPrefix(first, "http://") || strings.HasPrefix(first, "https://") || strings.HasPrefix(first, "-") {
			runProbe(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", first)
		fmt.Fprint(os.Stderr, topUsage)
		os.Exit(2)
	}
}

// probe subcommand

const probeUsage = `wafprobe probe — run multiple TLS personas against a target.

Usage:
  wafprobe probe [flags] <target-url>

Flags:
`

func runProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, probeUsage)
		fs.PrintDefaults()
	}

	var (
		jsonOut     = fs.Bool("json", false, "write JSON to stdout")
		quiet       = fs.Bool("q", false, "suppress banner and progress output")
		insecure    = fs.Bool("insecure", false, "skip TLS certificate verification")
		exitCode    = fs.Bool("exit-code", false, "exit non-zero if any persona was blocked (for CI)")
		personaList = fs.String("personas", "", "comma-separated persona IDs (default: all)")
		concurrency = fs.Int("concurrency", 4, "max parallel requests")
		timeout     = fs.Duration("timeout", 12*time.Second, "per-request timeout")
		proxy       = fs.String("proxy", "", "proxy URL: 'user:pass@host:port' OR 'host:port:user:pass' OR 'socks5://host:port'")
	)

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	target := fs.Arg(0)
	if err := requireHTTPS(target); err != nil {
		fatal(err)
	}

	personas, err := resolvePersonas(*personaList)
	if err != nil {
		fatal(err)
	}
	proxyURL, err := client.ParseProxy(*proxy)
	if err != nil {
		fatal(fmt.Errorf("--proxy: %w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !*quiet && !*jsonOut {
		fmt.Fprintf(os.Stderr, "wafprobe v%s — probing %s with %d persona(s)…\n", Version, target, len(personas))
	}

	runner := probe.NewRunner(probe.Options{
		Concurrency:        *concurrency,
		RequestTimeout:     *timeout,
		InsecureSkipVerify: *insecure,
		Proxy:              proxyURL,
	})
	results, err := runner.RunAll(ctx, target, personas)
	if err != nil {
		fatal(err)
	}

	if *jsonOut {
		if err := output.JSON(os.Stdout, target, results, Version); err != nil {
			fatal(err)
		}
	} else {
		if err := output.Pretty(os.Stdout, target, results, Version); err != nil {
			fatal(err)
		}
	}

	if *exitCode {
		for _, r := range results {
			if r.Detection.Blocked || r.Error != "" {
				os.Exit(1)
			}
		}
	}
}

// hunt subcommand

const huntUsage = `wafprobe hunt — surgically reverse-engineer what the WAF checks.

Runs ~20 probes, each mutating exactly ONE axis (TLS version, ALPN, SNI,
User-Agent, cookies, headers, HTTP method, etc.) and diffs the outcomes to
isolate which signals the target actually keys on.

For Shape, Kasada, PerimeterX, Akamai BMP — point at the actual auth-flow
endpoint with --method POST and a body, since those vendors only fire on
login / cart / checkout / API endpoints, not the homepage.

Usage:
  wafprobe hunt [flags] <target-url>

Examples:
  wafprobe hunt https://www.target.com
  wafprobe hunt --method POST --body '{"u":"x"}' --header "Content-Type: application/json" \
                https://api.uniqlo.com/us/auth/v1/login
  wafprobe hunt --persona go-stdlib --json https://target.com

Flags:
`

func runHunt(args []string) {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, huntUsage)
		fs.PrintDefaults()
	}

	var (
		jsonOut     = fs.Bool("json", false, "write JSON to stdout")
		quiet       = fs.Bool("q", false, "suppress progress logging")
		insecure    = fs.Bool("insecure", false, "skip TLS certificate verification")
		personaID   = fs.String("persona", "chrome-latest", "baseline persona id (see `wafprobe list`)")
		concurrency = fs.Int("concurrency", 4, "max parallel probes")
		timeout     = fs.Duration("timeout", 10*time.Second, "per-probe timeout")
		deep        = fs.Bool("deep", false, "intensive mode: run ~50 mutations instead of ~21 (Sec-Ch-Ua, Sec-Fetch-*, origin spoofing, more UAs / methods)")

		method      = fs.String("method", "GET", "HTTP method for the BASE request (GET/POST/PUT/...)")
		bodyArg     = fs.String("body", "", "request body. Inline string, or @path to read from file, or @- for stdin")
		cookie      = fs.String("cookie", "", "raw Cookie header sent on every probe (e.g. 'sess=abc; csrf=xyz')")
		proxy       = fs.String("proxy", "", "proxy URL: 'user:pass@host:port' OR 'host:port:user:pass' OR 'socks5://host:port'")
		personaFile = fs.String("persona-file", "", "path to a captured persona JSON (from `wafprobe import-har`). Sets baseline UA/headers/cookies/method/body to the real-browser snapshot.")
		http1       = fs.Bool("http1", false, "shortcut for ALPN: http/1.1 only (forces HTTP/1.1)")
	)
	headerFlag := newRepeatableStringFlag(fs, "header", "extra header on every probe (repeatable). Format: 'Name: value'")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	target := fs.Arg(0)
	if err := requireHTTPS(target); err != nil {
		fatal(err)
	}

	p, ok := persona.ByID(*personaID)
	if !ok {
		fatal(fmt.Errorf("unknown persona %q (use `wafprobe list`)", *personaID))
	}

	body, err := loadBody(*bodyArg)
	if err != nil {
		fatal(err)
	}
	headers, err := parseHeaders(*headerFlag)
	if err != nil {
		fatal(err)
	}
	proxyURL, err := client.ParseProxy(*proxy)
	if err != nil {
		fatal(fmt.Errorf("--proxy: %w", err))
	}

	// --persona-file fills in any flag the caller didn't explicitly set.
	if *personaFile != "" {
		captured, err := harimport.LoadCaptured(*personaFile)
		if err != nil {
			fatal(fmt.Errorf("--persona-file: %w", err))
		}
		// User-Agent
		if captured.UserAgent != "" {
			// Captured personas use stock TLS by default for replay accuracy.
			// We synthesize a one-off persona that overrides UA + uses chrome-latest TLS.
			p.UserAgent = captured.UserAgent
		}
		// Method (caller's --method wins if explicitly different from default GET)
		if *method == "GET" && captured.Method != "" {
			*method = captured.Method
		}
		// Body
		if len(body) == 0 {
			capBody, _ := captured.Body()
			body = capBody
		}
		// Cookie
		if *cookie == "" && captured.Cookie != "" {
			*cookie = captured.Cookie
		}
		// Headers — caller's --header wins per-key
		if headers == nil {
			headers = map[string]string{}
		}
		for k, v := range captured.Headers {
			if _, set := headers[k]; !set {
				headers[k] = v
			}
		}
		// If target wasn't given but captured has one, use it
		if target == "" && captured.URL != "" {
			target = captured.URL
		}
	}

	// --http1: force ALPN http/1.1 across every probe.
	var baselineALPN []string
	if *http1 {
		baselineALPN = []string{"http/1.1"}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mutations := hunt.AllMutations()
	if *deep {
		mutations = hunt.DeepMutations()
	}
	total := len(mutations)
	if !*quiet && !*jsonOut {
		bodyNote := ""
		if len(body) > 0 {
			bodyNote = fmt.Sprintf(", body=%dB", len(body))
		}
		modeNote := ""
		if *deep {
			modeNote = " DEEP"
		}
		proxyNote := ""
		if proxyURL != nil {
			proxyNote = fmt.Sprintf(" via proxy=%s://%s", proxyURL.Scheme, proxyURL.Host)
		}
		fmt.Fprintf(os.Stderr, "wafprobe hunt%s v%s — %d surgical probes on %s [%s%s]%s (baseline=%s)…\n",
			modeNote, Version, total, target, *method, bodyNote, proxyNote, p.ID)
	}

	logger := func(idx, total int, res hunt.MutationResult) {}
	if !*quiet && !*jsonOut {
		logger = func(idx, total int, res hunt.MutationResult) {
			fmt.Fprintf(os.Stderr, "  [%2d/%2d] %-36s → %s\n", idx, total, res.Mutation.Name, res.Outcome)
		}
	}

	rep, err := hunt.Run(ctx, target, hunt.Options{
		Persona:            p,
		InsecureSkipVerify: *insecure,
		Concurrency:        *concurrency,
		PerProbeTimeout:    *timeout,
		Logger:             logger,
		Method:             *method,
		Body:               body,
		ExtraHeaders:       headers,
		Cookie:             *cookie,
		Proxy:              proxyURL,
		Mutations:          mutations,
		BaselineALPN:       baselineALPN,
	})
	if err != nil {
		fatal(err)
	}

	if *jsonOut {
		if err := output.HuntJSON(os.Stdout, rep, Version); err != nil {
			fatal(err)
		}
	} else {
		if err := output.HuntPretty(os.Stdout, rep, Version); err != nil {
			fatal(err)
		}
	}
}

// import-har subcommand

const importHARUsage = `wafprobe import-har — extract a request shape from a HAR file.

Open Chrome DevTools → Network → reproduce the action you want to replay
(e.g. submit a login form). Right-click any request → "Save all as HAR with
content". Feed that file here. wafprobe extracts the User-Agent, every
header (including JS-injected ones like Shape's X-<id>-<letter> family or
Kasada's x-kpsdk-* headers), all cookies, the method, and the body — and
writes a "captured persona" JSON file.

Then point hunt or probe at the captured persona to REPLAY the exact
browser-shaped request the WAF was happy with — and run all axis mutations
on top of THAT shape.

Usage:
  wafprobe import-har [flags] <path-to-file.har>

Examples:
  wafprobe import-har devtools.har --filter "auth/login" -o cap.json
  wafprobe import-har devtools.har --list

Flags:
`

func runImportHAR(args []string) {
	fs := flag.NewFlagSet("import-har", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, importHARUsage)
		fs.PrintDefaults()
	}

	var (
		filter   = fs.String("filter", "", "URL substring to match (case-insensitive). If empty, picks first entry.")
		out      = fs.String("o", "", "output file path (default: <stem>-captured.json next to the HAR)")
		listFlag = fs.Bool("list", false, "list every entry's URL+method without writing anything")
		nameArg  = fs.String("name", "", "human-readable name for the captured persona (defaults to URL host + path)")
	)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	harPath := fs.Arg(0)

	h, err := harimport.Parse(harPath)
	if err != nil {
		fatal(err)
	}

	if *listFlag {
		for i, e := range h.Log.Entries {
			fmt.Printf("[%3d]  %-7s  %s\n", i, e.Request.Method, e.Request.URL)
		}
		return
	}

	entry, err := h.Pick(*filter)
	if err != nil {
		fatal(err)
	}

	id := generateCapturedID(entry.Request.URL)
	name := *nameArg
	if name == "" {
		name = id
	}
	captured := entry.ToCaptured(id, name)

	outPath := *out
	if outPath == "" {
		stem := strings.TrimSuffix(filepath.Base(harPath), filepath.Ext(harPath))
		outPath = filepath.Join(filepath.Dir(harPath), stem+"-captured.json")
	}

	if err := harimport.SaveCaptured(outPath, captured); err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stderr, "✓ captured persona written to %s\n", outPath)
	fmt.Fprintf(os.Stderr, "  %s\n", captured.Summarize())

	// Highlight known vendor-specific header families if present.
	notable := vendorNotable(captured.Headers)
	if len(notable) > 0 {
		fmt.Fprintf(os.Stderr, "  notable headers: %s\n", strings.Join(notable, ", "))
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  next: wafprobe hunt --persona-file %s %s\n", outPath, captured.URL)
}

// generateCapturedID returns a slug-ish id from a URL.
func generateCapturedID(rawURL string) string {
	id := rawURL
	for _, prefix := range []string{"https://", "http://"} {
		id = strings.TrimPrefix(id, prefix)
	}
	id = strings.ReplaceAll(id, "/", "-")
	id = strings.ReplaceAll(id, "?", "-")
	id = strings.ReplaceAll(id, "&", "-")
	id = strings.ReplaceAll(id, "=", "-")
	id = strings.Trim(id, "-")
	if len(id) > 60 {
		id = id[:60]
	}
	return "captured:" + id
}

// vendorNotable labels JS-injected header families (Shape, Kasada).
func vendorNotable(headers map[string]string) []string {
	var out []string
	shapeIDs := map[string]int{}
	kasadaCount := 0
	for k := range headers {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-kpsdk-") {
			kasadaCount++
		}
		// Shape X-<id>-<letter>: 8-char-ish id, then -<letter>[<digit>]
		if len(k) >= 6 && strings.HasPrefix(strings.ToLower(k), "x-") {
			parts := strings.Split(k, "-")
			if len(parts) == 3 && len(parts[1]) >= 6 && len(parts[1]) <= 12 {
				if len(parts[2]) >= 1 && len(parts[2]) <= 2 {
					shapeIDs[parts[1]]++
				}
			}
		}
	}
	for id, count := range shapeIDs {
		if count >= 2 {
			out = append(out, fmt.Sprintf("Shape sensor (id=%s, %d headers)", id, count))
		}
	}
	if kasadaCount > 0 {
		out = append(out, fmt.Sprintf("Kasada (x-kpsdk-* × %d)", kasadaCount))
	}
	return out
}

// list subcommand

func runList() {
	for _, id := range persona.IDs() {
		p, _ := persona.ByID(id)
		tag := ""
		if p.Randomized {
			tag += " (randomized)"
		}
		if p.UseStockTLS {
			tag += " (stock-tls)"
		}
		fmt.Printf("%-16s  %s%s\n", id, p.Name, tag)
	}
}

// helpers

func requireHTTPS(target string) error {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("target must start with http:// or https://")
	}
	return nil
}

func resolvePersonas(list string) ([]persona.Persona, error) {
	if list == "" {
		return persona.All(), nil
	}
	ids := strings.Split(list, ",")
	out := make([]persona.Persona, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		p, ok := persona.ByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown persona %q (use `wafprobe list`)", id)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid personas in %q", list)
	}
	return out, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// loadBody resolves a --body argument: "" = no body; "@-" = stdin;
// "@<path>" = file; otherwise the literal string.
func loadBody(arg string) ([]byte, error) {
	if arg == "" {
		return nil, nil
	}
	if arg == "@-" {
		return io.ReadAll(os.Stdin)
	}
	if strings.HasPrefix(arg, "@") {
		return os.ReadFile(arg[1:])
	}
	return []byte(arg), nil
}

// parseHeaders converts "Name: value" strings into a map.
func parseHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for _, line := range raw {
		idx := strings.IndexByte(line, ':')
		if idx < 1 {
			return nil, fmt.Errorf("malformed --header %q (expected 'Name: value')", line)
		}
		name := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if name == "" {
			return nil, fmt.Errorf("empty header name in --header %q", line)
		}
		out[name] = val
	}
	return out, nil
}

// repeatableStringFlag accumulates values across repeated flag occurrences.
type repeatableStringFlag []string

func (r *repeatableStringFlag) String() string { return strings.Join(*r, ", ") }
func (r *repeatableStringFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func newRepeatableStringFlag(fs *flag.FlagSet, name, usage string) *[]string {
	v := repeatableStringFlag{}
	fs.Var(&v, name, usage)
	return (*[]string)(&v)
}
