# wafprobe

[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/NotChaosuu/wafprobe?style=flat-square&color=orange)](https://github.com/NotChaosuu/wafprobe/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/NotChaosuu/wafprobe?style=flat-square)](https://goreportcard.com/report/github.com/NotChaosuu/wafprobe)

**Stop guessing why your scraper gets 403'd.**

wafprobe fires surgical probes that mutate one fingerprint axis at a time — TLS version, ALPN, SNI, User-Agent, headers — and tells you exactly which signals the WAF is checking. When something passes, it hands you a copy-paste curl line that reproduces it.

<!-- GIF GOES HERE — record with VHS: https://github.com/charmbracelet/vhs -->
<!-- Example: ![wafprobe demo](demo.gif) -->

---

## Install

**Prebuilt binary (fastest)**

```bash
# macOS / Linux
curl -sL https://github.com/NotChaosuu/wafprobe/releases/latest/download/wafprobe_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv wafprobe /usr/local/bin/

# Windows — download from Releases tab
```

**Go install**

```bash
go install github.com/NotChaosuu/wafprobe/cmd/wafprobe@latest
```

Needs Go 1.25 — utls 1.8 pinned us there. If you're on 1.24, build with an older utls (`go.mod` will need editing) — chrome-133 persona depends on a preset only in 1.8.

---

## Quick start

```
$ wafprobe hunt https://www.cloudflare.com

baseline (chrome-latest): pass — cloudflare

  force TLS 1.2          tls-version    pass
  ALPN: http/1.1 only    alpn           pass
  SNI: omit              sni            err
  UA: curl/8.0           user-agent     pass
  UA: Googlebot          user-agent     pass
  drop all cookies       cookies        pass
  ...

Target checks:  (none)
Target ignores: alpn, cookies, headers, method, tls-version, user-agent
Verdict: target passes baseline; nothing tested mattered.
```

---

## wafprobe vs wafw00f

wafw00f detects which WAF is present. wafprobe tells you **why** you're getting blocked and how to get through it.

| Feature | wafprobe | wafw00f |
|---|---|---|
| Per-axis fingerprint mutation | ✅ | ❌ |
| TLS / JA4 probing | ✅ | ❌ |
| Kasada, Shape, PerimeterX detection | ✅ | ❌ |
| HAR import for stateful replay | ✅ | ❌ |
| Copy-paste bypass curl output | ✅ | ❌ |
| Layer tagging (sensor / challenge / block) | ✅ | ❌ |
| POST mode with body + cookies | ✅ | ❌ |
| Proxy support (residential format) | ✅ | ❌ |
| Vendor detection only | ❌ | ✅ |
| Passive fingerprinting | ❌ | ✅ |

Use wafw00f when you just want vendor ID. Use wafprobe when you need to understand *what it's checking*.

---

## Why I built this

Built this after spending too many evenings trying to figure out why my scraper got 403'd on one site but not another. curl-impersonate worked here, broke there. Tweaking User-Agent did nothing on one target, fixed another. Couldn't tell which fingerprint axis any given WAF actually cared about, so I was guessing. wafprobe stops the guessing.

---

## How to use it

Two main commands:

**`probe`** — fast "what's even here" pass. Runs every built-in persona (Chrome / Firefox / Safari / iOS / stock Go / stock Python) in parallel.

```bash
wafprobe probe https://target.com
wafprobe probe --personas chrome-latest,go-stdlib https://target.com
```

**`hunt`** — runs 21 mutation probes (66 with `--deep`), each twiddling exactly one fingerprint axis. Use this when `probe` shows something getting blocked.

```bash
wafprobe hunt https://target.com
wafprobe hunt --deep https://target.com
```

**HAR import** — for sites with stateful JS-injected headers (Shape's `X-<id>-<letter>` family, Akamai's `_abck` cookie, Kasada's `x-kpsdk-*` tokens), you can't probe from scratch — the browser's JS sensor generates those values. But you can capture a real browser request and replay it:

```bash
# In Chrome DevTools → Network → "Save all as HAR with content"
wafprobe import-har -o cap.json --filter "auth/login" devtools.har
wafprobe hunt --persona-file cap.json https://api.target.com/auth/login
```

`import-har` will tag any Shape or Kasada signatures it finds in the captured headers, which is a quick way to confirm you grabbed the right request.

**POST mode** — for auth endpoints where bot protection actually fires:

```bash
wafprobe hunt --method POST \
  --body @login.json \
  --header "Content-Type: application/json" \
  --header "Origin: https://target.com" \
  --cookie "session=abc; csrf=xyz" \
  https://api.target.com/v1/auth/login
```

**Proxy support** — three formats:

```bash
--proxy user:pass@host:port          # URL format
--proxy host:port:user:pass          # residential panel format
--proxy socks5://host:port           # SOCKS5
```

Routes through both the utls path and the stock-Go path.

---

## What gets detected

Eight vendors, each with layer tagging — `pass`, `sensor` (profiling but not blocking), `http` (block page), `challenge` (JS interstitial), `rate-limit`:

| Vendor | Notes |
|---|---|
| **Cloudflare** | Distinguishes Managed Challenge (`cf_clearance` interstitial) vs Turnstile widget (the captcha on forms). Different problems, different solutions. |
| **Akamai** | Separates Bot Manager (`_abck`/`_bman`/`bm_sz`/`ak_bmsc`) from plain Akamai CDN. Lots of sites route through Akamai's CDN with Kasada or Shape doing the actual bot work — don't assume `Server: AkamaiGHost` means BM is on. |
| **DataDome** | Full detection |
| **PerimeterX / HUMAN** | Full detection |
| **Imperva / Incapsula** | Full detection |
| **AWS WAF** | Full detection |
| **Kasada** | `X-KPSDK-*` headers, `/ips.js` script, 429 default block |
| **Shape / F5 XC Bot Defense** | Pattern-matches the `X-<8char-id>-<letter>` request-header family using regex `X-[A-Za-z0-9]{6,12}-[A-Z][0-9]?`. Validated against real Uniqlo login traffic. |

Knowing the layer matters. "Sensor" means you can still get through — "challenge" means you need a different approach entirely.

---

## Limitations

A few honest limits, because the README would otherwise read like a brochure.

**TLS-version mutation does nothing on browser personas.** utls's preset `ClientHelloID`s hardcode `supported_versions` in their extension list. The mutation works correctly on `go-stdlib` and `python-requests`. If you specifically want to test TLS 1.2 rejection: `wafprobe hunt --persona go-stdlib`.

**Many bot-management vendors don't fire on the homepage.** Shape, Kasada, PerimeterX usually only engage on `/login`, `/cart`, `/api/auth/*`. If `probe` reports clean on a site you know has bot protection, point it at the auth endpoint.

**HTTP/2 SETTINGS frame fingerprinting isn't a probe axis yet.** Akamai BM and DataDome both inspect this. On the list.

**SNI omission is best-effort.** utls may still emit the extension regardless of what we ask. If `SNI: omit` shows as `err`, that's why.

**No JS challenge solving.** wafprobe diagnoses whether you need a JS solver — it doesn't be one.

---

## On Windows

If your URL has `&` in it, wrap it in double quotes:

```
wafprobe.exe hunt "https://target.com/path?a=1&b=2"
```

cmd.exe treats `&` as a command separator and will silently truncate the URL. PowerShell and POSIX shells handle it fine.

---

## Tests

```bash
go test ./...
```

~80% coverage across internal packages. CI runs on Linux, macOS, and Windows.

---

## Roadmap

- [ ] HTTP/2 SETTINGS frame fingerprinting (Akamai BM / DataDome)
- [ ] JA4 fingerprint export
- [ ] Antibot scoring (composite fingerprint risk score)
- [ ] JSON output mode for piping into other tools

---

## Related tools

Built alongside wafprobe for the recon pipeline:

- [**apkxray**](https://github.com/NotChaosuu/apkxray) — static APK triage: secrets, endpoints, SDKs, deep links
- [**authmap**](https://github.com/NotChaosuu/authmap) — map auth flows, find misconfigs, SQLi/XSS/CSRF/CORS
- [**tlsprint**](https://github.com/NotChaosuu/tlsprint) — see your TLS fingerprint as antibot systems see it

---

MIT License · [Chaosuu](https://t.me/chaosuudev) · [github.com/NotChaosuu](https://github.com/NotChaosuu)
