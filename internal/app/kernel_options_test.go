package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
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
	var err error
	dir := t.TempDir()
	port := freePort(t)
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
	if err := a.SetKernelOption("tun-stack", "system"); err != nil {
		t.Fatal(err)
	}
	if got := a.kernelOptions.Snapshot().TUNStack; got == nil || *got != "system" || a.model.TunStack != "System" {
		t.Fatal("TUN stack override not saved")
	}
	effective, err := a.core.EffectiveConfig()
	if err != nil || !strings.Contains(string(effective), "stack: system") {
		t.Fatal("TUN stack did not reach the kernel")
	}
	err = a.SetKernelOption("tun-stack", "mixed")
	if (err == nil) != features.WithGVisor {
		t.Fatalf("mixed stack capability mismatch: %v", err)
	}
	if err := a.SetKernelOption("tun-stack", "invalid"); err == nil {
		t.Fatal("invalid TUN stack accepted")
	}
	if err := a.SetKernelOption("tun-stack", ""); err != nil || a.kernelOptions.Snapshot().TUNStack != nil || a.model.TunStack != "跟随订阅" {
		t.Fatal("TUN stack inheritance not restored")
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

func TestAgentKernelOptionsPreserveConflictsAndRejectTUNTransition(t *testing.T) {
	dir := t.TempDir()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	v := true
	a.tunBusy = true
	if _, err := a.agentSetKernelOption(agent.KernelOptionArgs{Name: "ipv6", BoolValue: &v}); err == nil {
		t.Fatal("option changed during TUN transition")
	}
	a.tunBusy = false
	if _, err := a.agentSetKernelOption(agent.KernelOptionArgs{Name: "ipv6", BoolValue: &v, Inherit: true}); err == nil {
		t.Fatal("ambiguous option accepted")
	}
	if _, err := a.agentSetKernelOption(agent.KernelOptionArgs{Name: "ipv6", BoolValue: &v}); err != nil {
		t.Fatal(err)
	}
	proposal, err := a.agentPreview(agent.Change{Scope: "global", Operation: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kernel-options.json")
	external := []byte("{\"log_level\":\"debug\",\"future_field\":true}\n")
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentKernelOptions(); err == nil {
		t.Fatal("external options change was hidden")
	}
	if _, err := a.agentSetKernelOption(agent.KernelOptionArgs{Name: "ipv6", Inherit: true}); err == nil {
		t.Fatal("external options change was overwritten")
	}
	if _, err := a.agentPreview(agent.Change{Scope: "global", Operation: "clear"}); err == nil {
		t.Fatal("preview accepted externally modified options")
	}
	if _, err := a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("apply accepted externally modified options")
	}
	status, err := a.agentStatus()
	if err != nil || status.KernelOptionsWarning == "" {
		t.Fatalf("missing options conflict status: %+v %v", status, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(external) {
		t.Fatalf("external options lost: %q %v", got, err)
	}
}
