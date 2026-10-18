package persona

import (
	"strings"
	"testing"
)

// H2 fingerprints for Chrome and naked Go match known real-world values.
func TestAkamaiH2(t *testing.T) {
	for _, p := range All() {
		fp := AkamaiH2(p)
		if fp == "" {
			t.Errorf("persona %q has no H2 fingerprint", p.ID)
			continue
		}
		// four pipe-separated fields
		if got := strings.Count(fp, "|"); got != 3 {
			t.Errorf("persona %q H2 fp has %d '|', want 3: %q", p.ID, got, fp)
		}
	}

	chrome, _ := ByID("chrome-latest")
	if got := AkamaiH2(chrome); got != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Errorf("chrome H2 fingerprint = %q", got)
	}
	stock, _ := ByID("go-stdlib")
	if got := AkamaiH2(stock); got != "2:0;4:4194304;5:16384;6:10485760|1073741824|0|a,m,p,s" {
		t.Errorf("go-stdlib H2 fingerprint = %q", got)
	}
}
