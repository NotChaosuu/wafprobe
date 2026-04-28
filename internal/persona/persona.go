// Package persona defines client identities (TLS fingerprint + User-Agent)
// that wafprobe uses to issue requests against a target.
package persona

import (
	"sort"

	utls "github.com/refraction-networking/utls"
)

// Persona is a single client identity.
type Persona struct {
	// ID is a stable slug used on the CLI and in JSON output.
	ID string
	// Name is the human-readable label shown in reports.
	Name string
	// UserAgent is the HTTP User-Agent header this persona sends.
	UserAgent string
	// ClientHello is the utls preset used for TLS fingerprinting.
	// Ignored when UseStockTLS is true.
	ClientHello utls.ClientHelloID
	// Randomized is true for personas whose ClientHello shuffles extensions
	// across calls (modern Chrome 110+ mimics real browser anti-fingerprinting
	// by permuting extension order). JA3 hashes for Randomized personas will
	// legitimately vary between runs — downstream code must not assume stability.
	Randomized bool
	// UseStockTLS skips utls and uses Go's crypto/tls directly. Useful for
	// intentionally "bad" personas like go-stdlib / python-requests that
	// reveal what a naked script looks like to antibots.
	UseStockTLS bool
}

var registry = map[string]Persona{}

func register(p Persona) {
	if _, dup := registry[p.ID]; dup {
		panic("persona: duplicate id " + p.ID)
	}
	registry[p.ID] = p
}

// All returns every registered persona, sorted by ID for deterministic output.
func All() []Persona {
	out := make([]Persona, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ByID returns the persona with the given id, or false if it isn't registered.
func ByID(id string) (Persona, bool) {
	p, ok := registry[id]
	return p, ok
}

// IDs returns the sorted list of registered persona ids.
func IDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
