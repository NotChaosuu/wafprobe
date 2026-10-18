package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseProxy accepts URL form ([scheme://][user:pass@]host:port) or host:port:user:pass.
// Default scheme is http. A 4-part password containing '@' isn't supported.
func ParseProxy(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	if strings.Contains(s, "@") || strings.Contains(s, "://") {
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL: %w", err)
		}
		if u.Host == "" {
			return nil, errors.New("proxy URL missing host")
		}
		return u, nil
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2:
		return url.Parse("http://" + s)
	case 4:
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		if host == "" || port == "" {
			return nil, errors.New("proxy host:port:user:pass — empty host or port")
		}
		built := url.URL{
			Scheme: "http",
			User:   url.UserPassword(user, pass),
			Host:   net.JoinHostPort(host, port),
		}
		return &built, nil
	default:
		return nil, fmt.Errorf("unrecognized proxy format %q (expected scheme://[user:pass@]host:port OR host:port:user:pass)", s)
	}
}
