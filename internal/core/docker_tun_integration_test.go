//go:build linux && integration

package core

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func dockerIP(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %s: %v", args, out, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// Run only in a disposable Docker network namespace with CAP_NET_ADMIN and
// /dev/net/tun; this must never change the Windows host's active TUN device.
func TestDockerTUNLifecycle(t *testing.T) {
	if os.Getenv("NETFLOW_DOCKER_TUN") != "1" {
		t.Skip("requires explicit isolated Docker TUN test")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing TUN test outside Docker")
	}
	beforeRoutes := dockerIP(t, "-4", "route", "show", "table", "all")
	beforeRules := dockerIP(t, "-4", "rule", "show")
	dir := t.TempDir()
	config := `mixed-port: 0
port: 0
socks-port: 0
log-level: error
mode: rule
tun:
  enable: true
  device: netflow-test0
  stack: system
  auto-route: true
  auto-detect-interface: true
rules:
  - MATCH,DIRECT
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	if !c.Status().TUN {
		t.Fatal("kernel did not report TUN active")
	}
	if _, err := net.InterfaceByName("netflow-test0"); err != nil {
		t.Fatalf("missing TUN interface: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, err := net.InterfaceByName("netflow-test0")
		if err != nil && dockerIP(t, "-4", "route", "show", "table", "all") == beforeRoutes && dockerIP(t, "-4", "rule", "show") == beforeRules {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	afterRoutes := dockerIP(t, "-4", "route", "show", "table", "all")
	afterRules := dockerIP(t, "-4", "rule", "show")
	_, ifaceErr := net.InterfaceByName("netflow-test0")
	t.Fatalf("TUN cleanup failed: interface=%v\nroutes before:\n%s\nroutes after:\n%s\nrules before:\n%s\nrules after:\n%s", ifaceErr, beforeRoutes, afterRoutes, beforeRules, afterRules)
}
