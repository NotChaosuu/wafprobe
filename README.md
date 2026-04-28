# wafprobe

> **Point wafprobe at a target. It fires surgical probes — each mutating ONE fingerprint axis at a time — and tells you EXACTLY which signal the WAF is keying on, and which mutation gets through.**

Other tools stop at *"this site is protected by Cloudflare."* Cool. Now what? wafprobe answers **"what does the WAF actually check, and what gets through?"** in 30 seconds.

```
$ wafprobe hunt https://www.cloudflare.com

wafprobe hunt v0.3.0  target: https://www.cloudflare.com
──────────────────────────────────────────────────────────

  baseline (chrome-latest): pass — cloudflare

  surgical axis mutations (21 probes)

  MUTATION                              AXIS          RESULT
  force TLS 1.2                         tls-version   pass
  ALPN: http/1.1 only                   alpn          pass
  UA: Googlebot                         user-agent    pass
  add X-Forwarded-For: 127.0.0.1        headers       pass
  drop all cookies                      cookies       pass
  method: HEAD                          method        pass
  ...

╔══════════════════ REVERSE-ENGINEERED ══════════════════╗
║  Target checks:  (none)                                ║
║  Target ignores: alpn, cookies, headers, method, ...   ║
║  Verdict: target passes baseline; no axis mattered.    ║
╚════════════════════════════════════════════════════════╝
```

And on a hard target:

```
$ wafprobe hunt https://2captcha.com/demo/cloudflare-turnstile-challenge

  baseline (chrome-latest): block — cloudflare   ← even real Chrome fails

  [all 21 mutations blocked]

╔══════════════════ REVERSE-ENGINEERED ══════════════════╗
║  Verdict: no mutation passed. Target rejects every     ║
║  axis tested — likely needs JS-challenge solving.      ║
╚════════════════════════════════════════════════════════╝
```

---

## Quickstart

```bash
go install github.com/NotChaosuu/wafprobe/cmd/wafprobe@latest

wafprobe probe https://target.com                   # which client shapes does it block?
wafprobe hunt  https://target.com                   # 21 surgical probes
wafprobe hunt  --deep https://target.com            # 66 probes — adds Sec-Ch-Ua, Sec-Fetch-*, more UAs
wafprobe hunt  --method POST --body @payload.json https://api.target.com/login
wafprobe import-har -o cap.json devtools.har        # capture browser request from HAR
wafprobe hunt  --persona-file cap.json https://target.com
```

Requires **Go 1.25+**.

---

## Two modes

| Subcommand | What it does |
|---|---|
| `probe <url>` | Run all built-in TLS personas (Chrome / Firefox / Safari / iOS / stock Go / stock Python) and classify each response. **Good for:** "what WAF is here, and which client shapes get blocked?" |
| `hunt <url>` | Run 21 (or 66 with `--deep`) surgical axis-mutation probes and reverse-engineer which signal the WAF is keying on. **Good for:** "I'm getting 403'd — what specifically is the WAF checking?" |
| `import-har <file>` | Parse a Chrome / Firefox DevTools HAR export, extract the exact request shape (UA, all headers, cookies, body, method), write a captured persona JSON. Use it via `--persona-file` to replay your real browser. |
| `list` | Print all built-in persona IDs. |

Both `probe` and `hunt` support pretty terminal output AND JSON (`--json`).

---

## Why this exists

Existing tools stop at:

- **WAFW00F** — *"It's Cloudflare."* OK, I knew that.
- **curl-impersonate** — *"Here's a Chrome TLS library."* Which version? Which flag? For which site?
- **FlareSolverr** — *"Here's headless Chrome."* 500MB and slow.

wafprobe asks the question nobody automated before: **of the fingerprint axes my client exposes, which ones does *this specific target* actually inspect?** Bug bounty hunters and scraper devs answer that by hand over hours of trial-and-error. wafprobe does it in 30 seconds, and (when there's a passing mutation) prints a copy-paste curl line that reproduces the bypass.

---

## Install

```bash
go install github.com/NotChaosuu/wafprobe/cmd/wafprobe@latest
```

Or build from source:

```bash
git clone https://github.com/NotChaosuu/wafprobe.git
cd wafprobe
go build -o wafprobe ./cmd/wafprobe
```

Requires Go 1.25+.

---

## Usage

### `hunt` — surgical reverse-engineering

```bash
wafprobe hunt https://target.com
wafprobe hunt --persona go-stdlib https://target.com         # stock-Go baseline
wafprobe hunt --json https://target.com | jq '.findings'

# Auth-flow probing (Shape, Kasada, PerimeterX, Akamai BMP only fire on
# login / cart / checkout / API endpoints — not the homepage):
wafprobe hunt --method POST \
  --body '{"username":"test","password":"test"}' \
  --header "Content-Type: application/json" \
  --header "Origin: https://target.com" \
  --cookie "session=abc; csrf=xyz" \
  https://api.target.com/v1/auth/login
```

When the baseline blocks but a mutation passes, hunt prints a **copy-paste curl one-liner** at the bottom that reproduces the bypass. (No magic — you can also derive it manually from the table above. But it's a nice punchline.)

#### `--deep` (intensive mode, 66 probes)

```bash
wafprobe hunt --deep https://target.com
```

Adds 45 extra mutations on top of the base 21. New axes covered:
- **`client-hints`** — drop / fake / mobile-spoof Sec-Ch-Ua family
- **`sec-fetch`** — add or drop Sec-Fetch-Site/Mode/Dest
- **`origin-spoof`** — fake `True-Client-IP`, `CF-Connecting-IP`, `X-Originating-IP`, `X-Forwarded-Host`
- **More UAs** — Brave, Yandex, YandexBot, Discordbot, TelegramBot, LinkedInBot, Pinterest, Twitterbot, Samsung Internet, Opera, Vivaldi, iPad Safari, SemrushBot, AhrefsBot, Bingbot, DuckDuckBot, Applebot, archive.org_bot, Edge, Mobile Chrome (Android), WhatsApp link preview, Slackbot, facebookexternalhit
- **More headers** — DNT, Save-Data, Upgrade-Insecure-Requests, Priority (Chrome 124+), Cache-Control, Pragma, Range
- **More methods** — PURGE, TRACE, lowercase `get`
- **Combos** — "FULL Chrome 147 kit" (every realistic Sec-* + Priority header at once), "Googlebot UA + spoofed Google IP"

#### `import-har` + `--persona-file` (replay your real browser)

The escape hatch for sites with stateful JS-injected headers (Shape's `X-<id>-<letter>` family, Akamai BMP's `_abck` cookie, Kasada's `x-kpsdk-*` tokens). You can't generate these from scratch — but you CAN capture them once and replay them.

```bash
# 1) Open Chrome DevTools → Network → reproduce the action that gets blocked.
#    Right-click any request → "Save all as HAR with content".
# 2) Extract the request shape into a captured persona:
wafprobe import-har -o cap.json --filter "auth/login" devtools.har

# Output:
#   ✓ captured persona written to cap.json
#     [POST https://api.target.com/auth/login] UA: Mozilla/5.0 ..., Cookie: 4.2KB, Headers: 18, Body: 42 bytes
#     notable headers: Shape sensor (id=I1ysm4mm, 6 headers)
#
#     next: wafprobe hunt --persona-file cap.json https://api.target.com/auth/login

# 3) Hunt with the captured persona — the baseline is now your real browser:
wafprobe hunt --persona-file cap.json https://api.target.com/auth/login
```

`import-har` auto-detects Shape (`X-<id>-<letter>` family) and Kasada (`x-kpsdk-*`) sensor headers in the captured request and prints them — instant confirmation you grabbed the right traffic. (Other vendors don't inject characteristic request-side headers and aren't auto-tagged here, but the persona still replays them faithfully.)

#### `--proxy` (residential / scraping proxies)

```bash
wafprobe hunt --proxy user:pass@proxy.example.com:8080 https://target.com
wafprobe hunt --proxy proxy.example.com:8080:user:pass https://target.com    # IP-rotation 4-part format
wafprobe hunt --proxy socks5://proxy.example.com:1080 https://target.com
```

Both common notations supported. Schemes: `http://` (default), `https://`, `socks5://`. Auth optional. Pass-through to both the utls path and the stock-Go path. Limitation: if your 4-part password contains `@`, use URL form instead — the parser can't disambiguate.

#### Hunt flags

| Flag | What |
|---|---|
| `--persona ID` | baseline persona (default: `chrome-latest`) |
| `--persona-file PATH` | load a captured persona from a JSON file produced by `import-har` |
| `--method METHOD` | HTTP method for the BASE request (default: GET) |
| `--body STR` | request body (inline, `@/path/to/file`, or `@-` for stdin) |
| `--header "Name: value"` | extra header on every probe (repeatable) |
| `--cookie "..."` | raw Cookie header sent on every probe |
| `--proxy URL` | route every probe through a proxy (HTTP CONNECT or SOCKS5) |
| `--deep` | run 66 mutations instead of 21 |
| `--http1` | force ALPN `http/1.1` for the whole hunt |
| `--json` | JSON output to stdout |
| `-q` | suppress per-probe progress |
| `--timeout DUR` | per-probe timeout (default `10s`) |
| `--concurrency N` | parallel probes (default `4`) |
| `--insecure` | skip TLS cert verification |

#### Base mutation matrix (21 probes — `hunt` without `--deep`)

| Axis | Example mutations |
|---|---|
| `tls-version` | force TLS 1.2, force TLS 1.3 |
| `alpn` | http/1.1 only, h2 only, empty list |
| `sni` | omit SNI |
| `user-agent` | curl, Googlebot, empty, IE 6 |
| `cookies` | drop all cookies |
| `headers` | add X-Forwarded-For, X-Real-IP, Referer, Accept-Language; drop Accept / Accept-Encoding |
| `method` | HEAD, OPTIONS |
| `combo` | TLS 1.2 + ALPN, Googlebot + no cookies |

### `probe` — multi-persona classifier

```bash
wafprobe probe https://target.com
wafprobe probe --personas chrome-latest,go-stdlib https://target.com
wafprobe probe --json --exit-code https://target.com          # CI-friendly
wafprobe probe --proxy user:pass@host:port https://target.com
```

Real-world example:

```
$ wafprobe probe --personas chrome-latest,go-stdlib \
    'https://www.sweetwater.com/store/detail/RunnerHdp8--shure-srh840-closed-back-studio-headphones'

  PERSONA        STATUS  VENDOR      LAYER  DETAIL
  chrome-latest  200     -           pass   clean
  go-stdlib      403     perimeterx  http   body:perimeterx-challenge

  Summary: 1 passed, 1 blocked, 0 errored  (2 personas total)
  Vendors seen: perimeterx
```

---

## What's detected

WAF / bot-management vendors identified, with confidence levels and a layer taxonomy on every detection:

- **Cloudflare** — distinguishes Managed Challenge (`cf_clearance` interstitial) from Turnstile widget (form captcha)
- **Akamai** — separates Bot Manager (`_abck` / `_bman` / `bm_sz` / `ak_bmsc`) from plain Akamai CDN signals (`X-Akamai-Transformed`, `Server: AkamaiGHost`)
- **DataDome** — `datadome` cookie + captcha page
- **PerimeterX / HUMAN** — `_px`, `_pxvid`, challenge body
- **Imperva / Incapsula** — `x-iinfo`, incident ID
- **AWS WAF** — `x-amzn-waf-*`, `WAFBlockException`
- **Kasada** — `X-KPSDK-*`, `/ips.js`, 429 default block
- **Shape / F5 XC Bot Defense** — pattern-matches the `X-<id>-<letter>` request-header family (e.g. `X-I1ysm4mm-A`, `X-I1ysm4mm-Z: q`). The 8-char identifier is randomized per-deployment but stable per site. As far as we're aware, no other open-source tool detects Shape this way.

**Layer taxonomy** — every detection is classified as one of:

| Layer | Means |
|---|---|
| `pass` | clean, you got through |
| `sensor` | vendor is profiling but not blocking yet (e.g. Akamai `_abck` seed) |
| `http` | served a 4xx/5xx block |
| `challenge` | served a JS interstitial (CF Managed, Akamai sensor_data) |
| `rate-limit` | 429 |
| `tls` | handshake-level rejection |

---

## Personas

Run `wafprobe list` to see the full set:

| ID | Kind | Notes |
|---|---|---|
| `chrome-latest` | real browser (utls) | `HelloChrome_Auto` + Chrome 147 User-Agent |
| `chrome-133`, `chrome-131` | real browser | version-specific |
| `firefox-latest` | real browser | `HelloFirefox_120` TLS + Firefox 148 UA |
| `safari-17`, `ios-17` | real browser | Safari 16 / iOS 14 utls preset paired with current UAs |
| `go-stdlib` | **stock Go crypto/tls** | bypasses utls — shows what your naked scraper looks like |
| `python-requests` | **stock Go crypto/tls** | same TLS as go-stdlib but a different User-Agent — useful to separate "bad TLS" blocks from "bad UA" blocks |

---

## What wafprobe does NOT do

Honest list, so nobody downloads it expecting magic it doesn't have:

- ❌ **Does not bypass JS challenges** — Cloudflare Managed Challenge, Akamai sensor_data, DataDome captcha, PerimeterX captcha, Kasada KPSDK, Cloudflare Turnstile interactive. wafprobe diagnoses whether you need a JS solver; it doesn't BE one.
- ❌ **Does not generate Shape / Akamai / Kasada session tokens** — those are JS-sensor outputs, only the browser can produce them. wafprobe REPLAYS them via `import-har`, but doesn't synthesize new ones.
- ❌ **Does not simulate real user behavior** — no mouse movement, no timing, no JS execution, no canvas/WebGL fingerprint emulation. It's a transport-layer probe.
- ❌ **Does not solve CAPTCHAs** of any kind.
- ❌ **Does not crack HTTP/2 SETTINGS or pseudo-header order yet** — that's a probe axis on the roadmap; it requires forking `golang.org/x/net/http2` to control the SETTINGS frame, which is a non-trivial change.
- ❌ **Does not follow redirects with stateful cookie jars** — each probe is a single request.
- ❌ **Does not bypass IP / geo blocks** — if the target geo-blocks your IP, point through a residential proxy via `--proxy`.

---

## Heads-up: URL quoting on cmd.exe

If your target URL contains `&` (most query strings do), **wrap it in double quotes** on Windows cmd.exe — otherwise cmd.exe splits the command at `&` and only part of the URL reaches wafprobe. PowerShell and POSIX shells handle this fine.

```cmd
:: ✅ cmd.exe — double-quoted URL
wafprobe.exe hunt "https://target.com/path?a=1&b=2"

:: ❌ cmd.exe — unquoted, gets split at &
wafprobe.exe hunt https://target.com/path?a=1&b=2
```

The curl one-liners wafprobe emits use single quotes (POSIX convention). On cmd.exe, swap them for double quotes when pasting back.

## Known limitations

- **TLS version mutation** on browser personas (Chrome / Firefox / Safari / iOS) is a no-op — utls `ClientHelloID` presets hardcode `supported_versions` in their extension list, and `MinVersion` / `MaxVersion` knobs don't override it. The mutation works correctly on stock-TLS personas (`go-stdlib`, `python-requests`). Use `--persona go-stdlib` if you specifically want to test TLS-version gating.
- **HTTP/2 fingerprint** (SETTINGS frame values + order, pseudo-header order) is not yet a probe axis — see "What wafprobe does NOT do."
- **SNI omission** is best-effort; some utls versions still emit an SNI extension regardless.
- **Some high-protection sites do not engage their bot-management on the homepage** — Shape / Kasada / PerimeterX typically only fire on `/login`, `/checkout`, `/api/auth/*`. If `wafprobe probe` says "clean" on a target you know is protected, run it again against the deep URL.

---

## How it compares

| | wafprobe | WAFW00F | curl-impersonate | FlareSolverr |
|---|---|---|---|---|
| Identifies the WAF vendor | ✅ | ✅ | ❌ | CF-only |
| Classifies the block layer (TLS / HTTP / challenge / sensor / rate-limit) | ✅ | ❌ | ❌ | ❌ |
| Varies TLS fingerprint per probe | ✅ | ❌ | manual | ❌ |
| **Reverse-engineers which axis the WAF keys on** | ✅ | ❌ | ❌ | ❌ |
| **Replays a captured-from-HAR browser request** | ✅ | ❌ | ❌ | n/a |
| **Emits a copy-paste curl bypass when one passes** | ✅ | ❌ | ❌ | (solves CF directly) |
| Single static binary, Go | ✅ | Python | C | Python + Chromium |

---

## Testing

```bash
go test -count=1 ./...                 # all packages, ~1s
go test -v -count=1 ./...              # verbose, every subtest
go test -count=1 -cover ./...          # with coverage %
```

Coverage hovers around 80% across `internal/*`. CI runs on Linux + macOS + Windows.

---

## Part of the Chaosuu security toolkit

- [tlsprint](https://github.com/NotChaosuu/tlsprint) — see YOUR TLS fingerprint and what it looks like to antibots
- [authmap](https://github.com/NotChaosuu/authmap) — auth flow mapper + vulnerability scanner
- [apkxray](https://github.com/NotChaosuu/apkxray) — APK security analyzer
- **wafprobe** — what the WAF actually checks

## License

MIT

## Author

**Chaosuu** — [Telegram](https://t.me/chaosuudev) · [GitHub](https://github.com/NotChaosuu)
