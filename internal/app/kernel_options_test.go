package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestKernelOptionsApplyPersistAndRollbackOccupiedPort(t *testing.T) {
	dir := t.TempDir()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nallow-lan: false\nipv6: false\nmode: rule\nlog-level: error\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", port))
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err = a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core failed: %s", a.Home().Error)
	}
	preview, err := a.agentPreview(agent.Change{Scope: "global", Operation: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.SetKernelOption("ipv6", true); err != nil {
		t.Fatal(err)
	}
	if !a.core.Status().IPv6 || !a.model.Prefs.IPv6 {
		t.Fatal("IPv6 change not reflected in kernel and UI")
	}
	if _, err = a.agentApply(preview.ProposalID); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("stale proposal accepted: %v", err)
	}
	saved, err := kernelopts.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := saved.Snapshot().IPv6; v == nil || !*v {
		t.Fatal("option not persisted")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(base) {
		t.Fatal("subscription was modified")
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	busy := occupied.Addr().(*net.TCPAddr).Port
	if err = a.SetKernelPorts(ui.PortSet{Mixed: busy}); err == nil {
		t.Fatal("occupied port accepted")
	}
	if got := a.core.Status().MixedPort; got != port {
		t.Fatalf("original listener not restored: %d", got)
	}
	connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("original port not listening: %v", err)
	}
	_ = connection.Close()
	if v := a.kernelOptions.Snapshot().MixedPort; v != nil {
		t.Fatalf("failed port persisted: %d", *v)
	}
	if err := a.SetMode("direct"); err != nil {
		t.Fatal(err)
	}
	if a.core.Status().Mode != "direct" {
		t.Fatal("mode did not change")
	}
	if err := a.core.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Start(dir); err != nil {
		t.Fatal(err)
	}
	if !a.core.Status().IPv6 || a.core.Status().Mode != "direct" {
		t.Fatal("persisted override disappeared after core restart")
	}
	a.settings.SystemProxy = true
	if err = a.SetKernelPorts(ui.PortSet{Mixed: busy}); err == nil || !strings.Contains(err.Error(), "系统代理") {
		t.Fatalf("system proxy port guard: %v", err)
	}
}
