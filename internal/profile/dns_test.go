package profile

import (
	"strings"
	"testing"
)

func TestComposeDNSOverridesMergedAndKeepsInput(t *testing.T) {
	base := []byte("defaults: &d\n  dns:\n    enable: false\n<<: *d\nrules:\n  - MATCH,DIRECT\n")
	out, err := ComposeDNS(base, "enable: true\nlisten: 127.0.0.1:1053\nnameserver: [1.1.1.1]\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "listen: 127.0.0.1:1053") || !strings.Contains(string(base), "enable: false") {
		t.Fatal("override missing or original changed")
	}
	for _, bad := range []string{"", "[]", "dns: [", strings.Repeat("x", 65537)} {
		if _, err := ComposeDNS(base, bad); err == nil {
			t.Fatalf("invalid override accepted: %.20q", bad)
		}
	}
}
