//go:build !race

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalControllerListens(t *testing.T) {
	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nexternal-controller: %s\nsecret: test-secret\nrules:\n  - MATCH,DIRECT\n", addr)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	if err := waitListen(addr); err != nil {
		t.Fatal(err)
	}
}

func TestSafeController(t *testing.T) {
	for _, tc := range []struct {
		addr, secret string
		want         bool
	}{
		{"127.0.0.1:9097", "secret", true},
		{"[::1]:9097", "secret", true},
		{"127.0.0.1:9097", "", false},
		{"0.0.0.0:9097", "secret", false},
		{"192.168.1.1:9097", "secret", false},
		{"localhost:9097", "secret", false},
	} {
		if got := safeController(tc.addr, tc.secret); got != tc.want {
			t.Errorf("safeController(%q, ...)= %v", tc.addr, got)
		}
	}
}
