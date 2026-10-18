package ja4

import "testing"

var chromeCiphers = []uint16{
	0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xc02f, 0xc030,
	0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
}

func TestJA4B_RealChromeCipherHash(t *testing.T) {
	h := ClientHello{CipherSuites: chromeCiphers}
	got := ja4b(h)
	const want = "8daaf6152771"
	if got != want {
		t.Errorf("JA4_b(chrome ciphers) = %q, want %q (published Chrome value)", got, want)
	}
}

func TestJA4B_GREASEStrippedAndSorted(t *testing.T) {
	shuffled := []uint16{
		0x0a0a,
		0x0035, 0x1301, 0xcca8, 0x009c, 0xc02f, 0x002f, 0x1303,
		0xc030, 0x009d, 0xc013, 0x1302, 0xcca9, 0xc02b, 0xc014, 0xc02c,
	}
	if ja4b(ClientHello{CipherSuites: shuffled}) != "8daaf6152771" {
		t.Error("JA4_b not invariant to cipher order / GREASE injection")
	}
}

func TestJA4A_Assembly(t *testing.T) {
	h := ClientHello{
		TLSVersionMax: 0x0304,
		SNIPresent:    true,
		CipherSuites:  chromeCiphers,
		Extensions:    make([]uint16, 16),
		ALPN:          []string{"h2", "http/1.1"},
	}

	got := ja4a(h)
	const want = "t13d1516h2"
	if got != want {
		t.Errorf("JA4_a = %q, want %q", got, want)
	}
}

func TestJA4A_QUICandNoSNIandNoALPN(t *testing.T) {
	h := ClientHello{
		QUIC:          true,
		TLSVersionMax: 0x0304,
		SNIPresent:    false,
		CipherSuites:  []uint16{0x1301, 0x1302},
		Extensions:    []uint16{0x0000, 0x002b},
		ALPN:          nil,
	}
	got := ja4a(h)
	const want = "q13i020200"
	if got != want {
		t.Errorf("JA4_a = %q, want %q", got, want)
	}
}

func TestGREASEDetection(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xaaaa, 0xfafa, 0xbaba}
	for _, g := range grease {
		if !isGREASE(g) {
			t.Errorf("%#04x should be GREASE", g)
		}
	}
	notGrease := []uint16{0x1301, 0x0000, 0x002b, 0xc02f, 0x0a0b, 0x1a2a}
	for _, n := range notGrease {
		if isGREASE(n) {
			t.Errorf("%#04x should NOT be GREASE", n)
		}
	}
}

func TestJA4C_ExcludesSNIandALPN(t *testing.T) {
	withSNIALPN := ClientHello{Extensions: []uint16{0x0000, 0x0010, 0x002b, 0x000d, 0x0033}}
	without := ClientHello{Extensions: []uint16{0x002b, 0x000d, 0x0033}}
	if ja4c(withSNIALPN) != ja4c(without) {
		t.Error("JA4_c should exclude SNI (0x0000) and ALPN (0x0010) from the hash")
	}
}

func TestJA4C_EmptyCiphersIsZero(t *testing.T) {
	if ja4b(ClientHello{}) != zero12 {
		t.Error("empty cipher list should hash to the zero value")
	}
}

func TestFullJA4Deterministic(t *testing.T) {
	h := ClientHello{
		TLSVersionMax: 0x0304, SNIPresent: true,
		CipherSuites: chromeCiphers,
		Extensions:   []uint16{0x0000, 0x0010, 0x002b, 0x000d, 0x0033, 0x000a},
		SigAlgs:      []uint16{0x0403, 0x0804, 0x0401},
		ALPN:         []string{"h2"},
	}
	if JA4(h) != JA4(h) {
		t.Error("JA4 not deterministic")
	}
}

func TestJA4H_Assembly(t *testing.T) {
	r := HTTPRequest{
		Method: "GET",
		HTTP2:  true,
		Headers: []Header{
			{"sec-ch-ua", `"Chrome";v="151"`},
			{"user-agent", "Mozilla/5.0"},
			{"accept", "*/*"},
			{"accept-language", "en-US,en;q=0.9"},
			{"referer", "https://x.com"},
			{"cookie", "a=1"},
		},
		Cookies: []Cookie{{"a", "1"}},
	}

	got := ja4hA(r)
	const want = "ge20cr04enus"
	if got != want {
		t.Errorf("JA4H_a = %q, want %q", got, want)
	}
}

func TestJA4H_NoCookiesZero(t *testing.T) {
	r := HTTPRequest{Method: "POST", Headers: []Header{{"accept", "*/*"}}}
	if ja4hC(r) != zero12 || ja4hD(r) != zero12 {
		t.Error("no cookies should give zero c and d parts")
	}
}

func TestJA4H_CookieOrderInvariant(t *testing.T) {
	a := HTTPRequest{Cookies: []Cookie{{"z", "1"}, {"a", "2"}}}
	b := HTTPRequest{Cookies: []Cookie{{"a", "2"}, {"z", "1"}}}
	if ja4hC(a) != ja4hC(b) || ja4hD(a) != ja4hD(b) {
		t.Error("JA4H cookie parts should be order-invariant (sorted)")
	}
}

// non-alphanumeric method bytes get dropped from JA4H
func TestJA4HMethodSanitized(t *testing.T) {
	cases := []struct{ method, want string }{
		{"GET", "ge"},
		{"POST", "po"},
		{"a", "a0"},
		{"", "00"},
		{string([]byte{0xff, 0xfe}), "00"},     // raw bytes dropped
		{string([]byte{'g', 0x00, 't'}), "gt"}, // control byte skipped
	}
	for _, c := range cases {
		got := ja4hA(HTTPRequest{Method: c.method})[:2]
		if got != c.want {
			t.Errorf("ja4hA method for %q = %q, want %q", c.method, got, c.want)
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] >= 0x7f {
				t.Errorf("ja4hA(%q) method field has a raw byte: %q", c.method, got)
			}
		}
	}
}

func TestALPNCodeFollowsSpec(t *testing.T) {
	cases := []struct {
		alpn []string
		want string
	}{
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"-"}, "2d"},
		{[]string{}, "00"},
		{[]string{string([]byte{'h', 0xff})}, "6f"},
	}
	for _, c := range cases {
		if got := alpnCode(c.alpn); got != c.want {
			t.Errorf("alpnCode(%q) = %q, want %q", c.alpn, got, c.want)
		}
		if len(alpnCode(c.alpn)) != 2 {
			t.Errorf("alpnCode(%q) must be exactly 2 bytes, got %q", c.alpn, alpnCode(c.alpn))
		}
	}
}
