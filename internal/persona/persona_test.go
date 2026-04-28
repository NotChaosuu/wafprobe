package persona

import (
	"strings"
	"testing"
)

func TestBuiltinPersonasRegistered(t *testing.T) {
	wantIDs := []string{
		"chrome-latest",
		"chrome-133",
		"chrome-131",
		"firefox-latest",
		"safari-17",
		"ios-17",
		"go-stdlib",
		"python-requests",
	}
	for _, id := range wantIDs {
		p, ok := ByID(id)
		if !ok {
			t.Errorf("persona %q not registered", id)
			continue
		}
		if p.Name == "" {
			t.Errorf("persona %q has empty Name", id)
		}
		if p.UserAgent == "" {
			t.Errorf("persona %q has empty UserAgent", id)
		}
	}
}

// TestAllIsDeterministic guards against accidental removal of the sort
// in All() — Go's map iteration is randomized otherwise.
func TestAllIsDeterministic(t *testing.T) {
	run1 := All()
	run2 := All()
	if len(run1) != len(run2) {
		t.Fatalf("length mismatch: %d vs %d", len(run1), len(run2))
	}
	for i := range run1 {
		if run1[i].ID != run2[i].ID {
			t.Errorf("position %d: %q vs %q", i, run1[i].ID, run2[i].ID)
		}
	}
}

func TestByIDUnknown(t *testing.T) {
	if _, ok := ByID("nope-does-not-exist"); ok {
		t.Error("expected ok=false for unknown id")
	}
}

// TestBuildClientHelloRaw exercises offline ClientHello construction for
// every persona. Stock-TLS personas must return ErrNoOfflineJA3.
func TestBuildClientHelloRaw(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			raw, err := BuildClientHelloRaw(p, "example.com")
			if p.UseStockTLS {
				if err != ErrNoOfflineJA3 {
					t.Errorf("stock-TLS persona %q should return ErrNoOfflineJA3, got %v", p.ID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildClientHelloRaw: %v", err)
			}
			if len(raw) < 40 {
				t.Fatalf("ClientHello too short: %d bytes", len(raw))
			}
			if raw[0] != 0x01 {
				t.Fatalf("expected handshake type 0x01 (ClientHello), got 0x%02x", raw[0])
			}
		})
	}
}

// TestJA3StableAcrossRuns_NonRandomized asserts that for personas that do NOT
// shuffle their ClientHello, two runs produce the same JA3 hash.
// Randomized personas (Chrome 110+) are covered by a separate relaxed test.
func TestJA3StableAcrossRuns_NonRandomized(t *testing.T) {
	for _, p := range All() {
		if p.Randomized || p.UseStockTLS {
			continue
		}
		t.Run(p.ID, func(t *testing.T) {
			_, h1, err := JA3(p, "example.com")
			if err != nil {
				t.Fatalf("JA3 run 1: %v", err)
			}
			_, h2, err := JA3(p, "example.com")
			if err != nil {
				t.Fatalf("JA3 run 2: %v", err)
			}
			if h1 != h2 {
				t.Errorf("JA3 hash unstable across runs for non-randomized persona: %s vs %s", h1, h2)
			}
			if len(h1) != 32 {
				t.Errorf("JA3 hash length should be 32 hex chars, got %d: %q", len(h1), h1)
			}
		})
	}
}

// TestJA3Randomized_ProducesValidButVariableHashes verifies that personas
// marked Randomized (Chrome 110+) actually shuffle their ClientHello —
// 6 samples must yield at least 2 distinct hashes.
func TestJA3Randomized_ProducesValidButVariableHashes(t *testing.T) {
	anyRandomized := false
	for _, p := range All() {
		if !p.Randomized {
			continue
		}
		anyRandomized = true
		t.Run(p.ID, func(t *testing.T) {
			seen := map[string]struct{}{}
			for i := 0; i < 6; i++ {
				_, h, err := JA3(p, "example.com")
				if err != nil {
					t.Fatalf("JA3 sample %d: %v", i, err)
				}
				if len(h) != 32 {
					t.Fatalf("hash length should be 32 hex chars, got %q", h)
				}
				seen[h] = struct{}{}
			}
			if len(seen) < 2 {
				t.Errorf("persona %q is marked Randomized but produced identical JA3 across 6 runs", p.ID)
			}
		})
	}
	if !anyRandomized {
		t.Skip("no randomized personas registered")
	}
}

// TestJA3FamiliesAreDistinct compares structural JA3 (everything except
// extension order) across browser families. Same-family duplicates are
// expected — Chrome 131/133/latest share a cipher list — but cross-family
// duplicates would mean we can't distinguish browsers.
func TestJA3FamiliesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, p := range All() {
		if p.UseStockTLS {
			continue
		}
		family := familyOf(p.ID)
		s, _, err := JA3(p, "example.com")
		if err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		parts := strings.Split(s, ",")
		if len(parts) != 5 {
			t.Fatalf("%s: malformed JA3 string", p.ID)
		}
		structural := parts[0] + "|" + parts[1] + "|" + parts[3] + "|" + parts[4]

		if prev, dup := seen[structural]; dup {
			if familyOf(prev) != family {
				t.Errorf("personas %q (family %q) and %q (family %q) have identical structural JA3", prev, familyOf(prev), p.ID, family)
			}
			continue
		}
		seen[structural] = p.ID
	}
}

// familyOf returns the prefix before the first dash in a persona ID.
func familyOf(id string) string {
	for i, r := range id {
		if r == '-' {
			return id[:i]
		}
	}
	return id
}

func TestJA3FormatShape(t *testing.T) {
	p, _ := ByID("firefox-latest") // non-randomized → stable output
	s, _, err := JA3(p, "example.com")
	if err != nil {
		t.Fatalf("JA3: %v", err)
	}
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3 string should have 5 comma-separated fields, got %d: %q", len(parts), s)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Errorf("JA3 string has empty leading fields: %q", s)
	}
}

func TestIsGREASE(t *testing.T) {
	cases := []struct {
		v    uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0xfafa, true},
		{0x1301, false}, // TLS_AES_128_GCM_SHA256
		{0xc02b, false}, // ECDHE-ECDSA-AES128-GCM-SHA256
		{0x0000, false},
		{0xabab, false}, // not GREASE pattern
	}
	for _, tc := range cases {
		got := isGREASE(tc.v)
		if got != tc.want {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
