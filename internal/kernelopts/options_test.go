package kernelopts

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestTUNStackOverridePreservesAnchorsAndOtherFields(t *testing.T) {
	base := []byte("common: &base\n  enable: false\n  stack: mixed\n  mtu: 1400\ntun: *base\nother: *base\n")
	stack := "system"
	out, err := Compose(base, Options{TUNStack: &stack})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Tun struct {
			Enable bool   `yaml:"enable"`
			Stack  string `yaml:"stack"`
			MTU    int    `yaml:"mtu"`
		} `yaml:"tun"`
		Other struct {
			Stack string `yaml:"stack"`
		} `yaml:"other"`
	}
	if err = yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Tun.Enable || parsed.Tun.Stack != "system" || parsed.Tun.MTU != 1400 || parsed.Other.Stack != "mixed" {
		t.Fatalf("bad composition %+v", parsed)
	}
	if !strings.Contains(string(base), "tun: *base") {
		t.Fatal("source was changed")
	}
	bad := "unknown"
	if _, err = Compose(base, Options{TUNStack: &bad}); err == nil {
		t.Fatal("invalid stack accepted")
	}
	if _, err = Compose([]byte("tun: [bad]\n"), Options{TUNStack: &stack}); err == nil {
		t.Fatal("invalid TUN mapping accepted")
	}
}
