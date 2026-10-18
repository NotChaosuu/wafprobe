package hunt

import (
	"strings"
	"testing"

	"github.com/NotChaosuu/wafprobe/internal/client"
)

func newOptionsForTest() *client.Options { return &client.Options{} }

// TestDeepMutationsExtendsAll: DeepMutations is a superset of AllMutations.
func TestDeepMutationsExtendsAll(t *testing.T) {
	base := AllMutations()
	deep := DeepMutations()
	if len(deep) <= len(base) {
		t.Fatalf("expected DeepMutations to add extras (deep=%d, base=%d)", len(deep), len(base))
	}
	if len(deep) < 40 {
		t.Errorf("expected ~50 deep mutations, got %d (too few — coverage suffers)", len(deep))
	}

	deepNames := map[string]struct{}{}
	for _, m := range deep {
		deepNames[m.Name] = struct{}{}
	}
	for _, b := range base {
		if _, ok := deepNames[b.Name]; !ok {
			t.Errorf("deep set missing base mutation %q", b.Name)
		}
	}
}

// TestDeepMutationsAreDistinct: no duplicate names.
func TestDeepMutationsAreDistinct(t *testing.T) {
	seen := map[string]struct{}{}
	for _, m := range DeepMutations() {
		if _, dup := seen[m.Name]; dup {
			t.Errorf("duplicate mutation name in deep set: %q", m.Name)
		}
		seen[m.Name] = struct{}{}
		if m.Apply == nil {
			t.Errorf("mutation %q has nil Apply", m.Name)
		}
		if m.Axis == "" {
			t.Errorf("mutation %q has empty Axis", m.Name)
		}
	}
}

// TestDeepMutationsCoverNewAxes: deep adds client-hints, sec-fetch, origin-spoof.
func TestDeepMutationsCoverNewAxes(t *testing.T) {
	wantNewAxes := []string{"client-hints", "sec-fetch", "origin-spoof"}
	axes := map[string]struct{}{}
	for _, m := range DeepMutations() {
		axes[m.Axis] = struct{}{}
	}
	for _, want := range wantNewAxes {
		if _, ok := axes[want]; !ok {
			t.Errorf("deep set missing expected axis %q", want)
		}
	}
}

// TestDeepMutation_FullChromeKit_AppliesAllExpectedHeaders: every Sec-*/Priority header is set.
func TestDeepMutation_FullChromeKit_AppliesAllExpectedHeaders(t *testing.T) {
	var fullKit Mutation
	for _, m := range DeepMutations() {
		if m.Name == "FULL Chrome 152 client-hints kit" {
			fullKit = m
			break
		}
	}
	if fullKit.Apply == nil {
		t.Fatal("could not find 'FULL Chrome 152 client-hints kit' mutation")
	}

	o := newOptionsForTest()
	fullKit.Apply(o)

	hval := func(name string) (string, bool) {
		for _, h := range o.ExtraHeaders {
			if strings.EqualFold(h.Name, name) {
				return h.Value, true
			}
		}
		return "", false
	}
	expected := []string{"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
		"Upgrade-Insecure-Requests", "Priority"}
	for _, h := range expected {
		if _, ok := hval(h); !ok {
			t.Errorf("FULL kit missing header %q", h)
		}
	}
	if v, _ := hval("Sec-Ch-Ua"); !strings.Contains(v, "152") {
		t.Errorf("Sec-Ch-Ua should reference Chrome 152, got %q", v)
	}
}
