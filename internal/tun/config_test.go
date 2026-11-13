package tun

import (
	"github.com/metacubex/mihomo/constant/features"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestUseDefaultsAndDisable(t *testing.T) {
	got := Use(map[string]any{"mode": "rule", "ipv6": true}, true)
	tunm := got["tun"].(map[string]any)
	if tunm["enable"] != true || tunm["stack"] != DefaultStack || tunm["auto-route"] != true {
		t.Fatalf("tun %#v", tunm)
	}
	hijack, _ := tunm["dns-hijack"].([]any)
	if len(hijack) != 1 || hijack[0] != DefaultDNSHijack {
		t.Fatalf("hijack %#v", tunm["dns-hijack"])
	}
	dns := got["dns"].(map[string]any)
	if dns["enable"] != true || dns["enhanced-mode"] != "fake-ip" || dns["fake-ip-range"] != "198.18.0.1/16" || dns["fake-ip-range6"] != "2001:2::0/64" {
		t.Fatalf("dns %#v", dns)
	}
	if got["mode"] != "rule" {
		t.Fatal("mode dropped")
	}

	off := Use(got, false)
	if off["tun"].(map[string]any)["enable"] != false {
		t.Fatal("disable")
	}
	if off["dns"].(map[string]any)["enhanced-mode"] != "fake-ip" {
		t.Fatal("disable changed dns")
	}

	redir := Use(map[string]any{"dns": map[string]any{"enhanced-mode": "redir-host", "enable": false}}, true)
	if redir["dns"].(map[string]any)["enable"] != false {
		t.Fatal("non fake-ip dns was forced on")
	}
}

func TestApplyFileDoesNotStartKernel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("mode: rule\nmixed-port: 7897\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFile(path, true); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"enable: true", "mips", "auto-route: true", "any:53", "fake-ip"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
}

func TestSupportedStacksMatchBuild(t *testing.T) {
	stacks := SupportedStacks()
	if !slices.Contains(stacks, "system") || !slices.Contains(stacks, "mips") || slices.Contains(stacks, "mixed") != features.WithGVisor || slices.Contains(stacks, "gvisor") != features.WithGVisor {
		t.Fatalf("stacks=%v gvisor=%v", stacks, features.WithGVisor)
	}
}
