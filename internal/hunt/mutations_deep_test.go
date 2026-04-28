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

	// Every base mutation name should appear in deep.
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

// TestDeepMutation_FullChromeKit_AppliesAllExpectedHeaders: the combo
// mutation populates every Sec-* / Priority header we expect.
func TestDeepMutation_FullChromeKit_AppliesAllExpectedHeaders(t *testing.T) {
	var fullKit Mutation
	for _, m := range DeepMutations() {
		if m.Name == "FULL Chrome 147 client-hints kit" {
			fullKit = m
			break
		}
	}
	if fullKit.Apply == nil {
		t.Fatal("could not find 'FULL Chrome 147 client-hints kit' mutation")
	}

	opts := struct {
		ExtraHeaders map[string]string
	}{}
	// Apply needs a *client.Options; build one and check the resulting headers.
	o := newOptionsForTest()
	fullKit.Apply(o)

	expected := []string{"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
		"Upgrade-Insecure-Requests", "Priority"}
	for _, h := range expected {
		if _, ok := o.ExtraHeaders[h]; !ok {
			t.Errorf("FULL kit missing header %q", h)
		}
	}
	// Sec-Ch-Ua value should reference Chrome 147.
	if !strings.Contains(o.ExtraHeaders["Sec-Ch-Ua"], "147") {
		t.Errorf("Sec-Ch-Ua should reference Chrome 147, got %q", o.ExtraHeaders["Sec-Ch-Ua"])
	}
	_ = opts
}
