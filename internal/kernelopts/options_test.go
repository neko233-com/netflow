package kernelopts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestStorePreservesExternalOptions(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := true
	if err := s.Replace(Options{IPv6: &v}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kernel-options.json")
	external := []byte("{\"allow_lan\":true,\"future_field\":17}\n")
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCurrent(); !errors.Is(err, ErrConflict) {
		t.Fatalf("check: %v", err)
	}
	if err := s.Replace(Options{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(external) {
		t.Fatalf("external data lost: %q %v", got, err)
	}
	if s.Snapshot().IPv6 == nil || !*s.Snapshot().IPv6 {
		t.Fatal("in-memory value changed on conflict")
	}
	if err := os.WriteFile(path, []byte("{} {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

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
