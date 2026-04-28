package client

import (
	"net/url"
	"testing"
)

func TestParseProxy(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantNil  bool
		wantErr  bool
		wantHost string
		wantUser string
		wantPass string
		wantSch  string
	}{
		{"empty → nil", "", true, false, "", "", "", ""},
		{"plain host:port", "proxy.example.com:8080", false, false, "proxy.example.com:8080", "", "", "http"},
		{"URL form with auth", "user:pass@proxy.example.com:8080", false, false, "proxy.example.com:8080", "user", "pass", "http"},
		{"URL form scheme + auth", "http://user:pass@proxy.example.com:8080", false, false, "proxy.example.com:8080", "user", "pass", "http"},
		{"socks5 with auth", "socks5://u:p@proxy.example.com:1080", false, false, "proxy.example.com:1080", "u", "p", "socks5"},
		{"socks5 no auth", "socks5://proxy.example.com:1080", false, false, "proxy.example.com:1080", "", "", "socks5"},
		{"https proxy", "https://user:pass@proxy.example.com:8443", false, false, "proxy.example.com:8443", "user", "pass", "https"},

		// IP-rotation 4-part form (host:port:user:pass)
		{"4-part rotation", "proxy.example.com:8080:user:pass", false, false, "proxy.example.com:8080", "user", "pass", "http"},
		{"4-part with IP host", "1.2.3.4:8000:rotaty:simplepass", false, false, "1.2.3.4:8000", "rotaty", "simplepass", "http"},
		// Note: '@' inside a 4-part password is documented as unsupported
		// (use URL form instead). Skipping that ambiguous case.

		// errors
		{"3 parts is ambiguous garbage", "host:port:user", false, true, "", "", "", ""},
		{"empty host in 4-part", ":8080:u:p", false, true, "", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := ParseProxy(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got url=%v", u)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if c.wantNil {
				if u != nil {
					t.Errorf("expected nil URL for empty input, got %v", u)
				}
				return
			}
			if u == nil {
				t.Fatal("expected non-nil URL")
			}
			if u.Host != c.wantHost {
				t.Errorf("host=%q want %q", u.Host, c.wantHost)
			}
			if u.Scheme != c.wantSch {
				t.Errorf("scheme=%q want %q", u.Scheme, c.wantSch)
			}
			if c.wantUser != "" {
				if u.User == nil {
					t.Errorf("expected user, got nil userinfo")
				} else if u.User.Username() != c.wantUser {
					t.Errorf("user=%q want %q", u.User.Username(), c.wantUser)
				}
				if pw, _ := u.User.Password(); pw != c.wantPass {
					t.Errorf("pass=%q want %q", pw, c.wantPass)
				}
			} else if u.User != nil {
				t.Errorf("expected no user, got %v", u.User)
			}
		})
	}
}

func TestParseProxy_RoundtripURL(t *testing.T) {
	// Parsed proxy URLs must round-trip through url.Parse.
	u, err := ParseProxy("user:pass@proxy.example.com:8080")
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := url.Parse(u.String())
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if roundtrip.Host != u.Host {
		t.Errorf("host changed across roundtrip: %q vs %q", roundtrip.Host, u.Host)
	}
}
