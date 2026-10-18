package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type ClientHello struct {
	QUIC          bool
	TLSVersionMax uint16
	SNIPresent    bool
	CipherSuites  []uint16
	Extensions    []uint16
	SigAlgs       []uint16
	ALPN          []string
}

func JA4(h ClientHello) string {
	return fmt.Sprintf("%s_%s_%s", ja4a(h), ja4b(h), ja4c(h))
}

func ja4a(h ClientHello) string {
	proto := "t"
	if h.QUIC {
		proto = "q"
	}
	sni := "i"
	if h.SNIPresent {
		sni = "d"
	}
	ciphers := stripGREASE(h.CipherSuites)
	exts := stripGREASE(h.Extensions)
	return fmt.Sprintf("%s%s%s%s%s%s",
		proto,
		tlsVersion(h.TLSVersionMax),
		sni,
		count2(len(ciphers)),
		count2(len(exts)),
		alpnCode(h.ALPN),
	)
}

func ja4b(h ClientHello) string {
	ciphers := stripGREASE(h.CipherSuites)
	if len(ciphers) == 0 {
		return zero12
	}
	sorted := append([]uint16(nil), ciphers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return truncSHA256(hexList(sorted))
}

func ja4c(h ClientHello) string {
	exts := stripGREASE(h.Extensions)

	filtered := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		filtered = append(filtered, e)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })

	base := hexList(filtered)
	sigalgs := stripGREASE(h.SigAlgs)
	if len(sigalgs) > 0 {
		base = base + "_" + hexList(sigalgs)
	}
	return truncSHA256(base)
}

type Header struct {
	Name  string
	Value string
}

type Cookie struct {
	Name  string
	Value string
}

type HTTPRequest struct {
	Method  string
	HTTP2   bool
	Headers []Header
	Cookies []Cookie
}

func JA4H(r HTTPRequest) string {
	return fmt.Sprintf("%s_%s_%s_%s", ja4hA(r), ja4hB(r), ja4hC(r), ja4hD(r))
}

func ja4hA(r HTTPRequest) string {
	method := methodCode(r.Method)

	ver := "11"
	if r.HTTP2 {
		ver = "20"
	}

	cookie := "n"
	referer := "n"
	counted := 0
	for _, hd := range r.Headers {
		switch hd.Name {
		case "cookie":
			cookie = "c"
		case "referer":
			referer = "r"
		default:
			counted++
		}
	}

	return fmt.Sprintf("%s%s%s%s%s%s", method, ver, cookie, referer, count2(counted), acceptLang(r.Headers))
}

func ja4hB(r HTTPRequest) string {
	names := make([]string, 0, len(r.Headers))
	for _, hd := range r.Headers {
		if hd.Name == "cookie" || hd.Name == "referer" {
			continue
		}
		names = append(names, hd.Name)
	}
	if len(names) == 0 {
		return zero12
	}
	return truncSHA256(strings.Join(names, ","))
}

func ja4hC(r HTTPRequest) string {
	if len(r.Cookies) == 0 {
		return zero12
	}
	names := make([]string, len(r.Cookies))
	for i, c := range r.Cookies {
		names[i] = c.Name
	}
	sort.Strings(names)
	return truncSHA256(strings.Join(names, ","))
}

func ja4hD(r HTTPRequest) string {
	if len(r.Cookies) == 0 {
		return zero12
	}
	pairs := make([]string, len(r.Cookies))
	for i, c := range r.Cookies {
		pairs[i] = c.Name + "=" + c.Value
	}
	sort.Strings(pairs)
	return truncSHA256(strings.Join(pairs, ","))
}

const zero12 = "000000000000"

func isGREASE(v uint16) bool {
	return (v>>8) == (v&0xff) && (v&0x0f) == 0x0a
}

func stripGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func tlsVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

// methodCode is the JA4H method field: first two alnum chars of the lowercased
// method, '0'-padded. other bytes are dropped since :method is client-controlled.
func methodCode(m string) string {
	out := make([]byte, 0, 2)
	for i := 0; i < len(m) && len(out) < 2; i++ {
		c := m[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if isAlnum(c) {
			out = append(out, c)
		}
	}
	for len(out) < 2 {
		out = append(out, '0')
	}
	return string(out)
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// alpnCode per the JA4 spec: first+last alnum chars of the first ALPN, or of its
// hex if either end isn't alnum. keeps raw NUL/CR/LF out of the fingerprint.
func alpnCode(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	s := alpn[0]
	first, last := s[0], s[len(s)-1]
	if isAlnum(first) && isAlnum(last) {
		return string(first) + string(last)
	}
	h := hex.EncodeToString([]byte(s))
	return string(h[0]) + string(h[len(h)-1])
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func acceptLang(headers []Header) string {
	for _, hd := range headers {
		if hd.Name != "accept-language" {
			continue
		}
		v := strings.ToLower(hd.Value)
		v = strings.NewReplacer("-", "", ";", "").Replace(v)
		rs := []rune(v)
		if len(rs) > 4 {
			rs = rs[:4]
		}
		out := string(rs)
		for len([]rune(out)) < 4 {
			out += "0"
		}
		return out
	}
	return "0000"
}

func hexList(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func truncSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
