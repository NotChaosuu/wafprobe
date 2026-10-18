// Package persona defines client identities: TLS and HTTP/2 fingerprint,
// ordered headers and User-Agent, backed by bogdanfinn/tls-client profiles.
package persona

import (
	"sort"

	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// HeaderField is one request header in send order.
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Persona is a single client identity.
type Persona struct {
	ID        string
	Name      string
	UserAgent string
	// Profile is what goes on the wire, and the source of the offline JA3/JA4.
	Profile profiles.ClientProfile
	// Headers in send order, without User-Agent (inserted from UserAgent).
	Headers []HeaderField
	// Randomized: extension order shuffles per handshake (modern Chrome), so JA3
	// varies between runs and JA4 doesn't.
	Randomized bool
	// Stock marks the naked-script personas (go-stdlib, python-requests).
	Stock bool
}

// Hello returns the utls ClientHelloID backing this persona.
func (p Persona) Hello() tls.ClientHelloID {
	return p.Profile.GetClientHelloId()
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

// retired id -> current id, so old scripts keep working
var aliases = map[string]string{
	"safari-17": "safari-16", // renamed in 0.5.0 (the profile was always Safari 16)
}

// Alias returns the current id for a retired one, or "" if id isn't an alias.
func Alias(id string) string { return aliases[id] }

// ByID returns the persona with the given id, resolving aliases.
func ByID(id string) (Persona, bool) {
	if canon, ok := aliases[id]; ok {
		id = canon
	}
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
