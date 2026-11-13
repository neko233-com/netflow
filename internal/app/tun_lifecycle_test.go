package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestTUNStartupFailureFallsBackWithoutChangingSource(t *testing.T) {
	t.Setenv("CI", "1")
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ntun: {enable: true}\nrules: ['MATCH,DIRECT']\n")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	store := appconfig.NewMemory(dir)
	if err := store.Save(appconfig.Settings{TUN: true}); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running || a.core.Status().TUN || a.Home().TUN || !strings.Contains(a.model.Notice, "虚拟网卡启动失败") {
		t.Fatalf("fallback state: %+v", a.Home())
	}
	saved, err := store.Load()
	if err != nil || saved.TUN {
		t.Fatal("failed TUN choice remained enabled")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(base) {
		t.Fatal("source config changed")
	}
}

func TestSubscriptionCannotEnableTUNWithoutExplicitChoice(t *testing.T) {
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ntun: {enable: true}\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running || a.core.Status().TUN || a.Home().TUN {
		t.Fatal("subscription activated TUN without user choice")
	}
}

// A conflicting tunnel is rejected before the core or persisted settings change.
type conflictTUN struct{ *tun.Memory }

func (c *conflictTUN) CheckHost() error { return errors.New("other tunnel active") }

func TestTUNPreflightDoesNotChangeConfiguration(t *testing.T) {
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	store := appconfig.NewMemory(dir)
	controller := &conflictTUN{tun.NewMemory()}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: sysproxy.NewMemory(), TUN: controller, Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if err := a.SetTUN(true); err == nil || !strings.Contains(err.Error(), "other tunnel") {
		t.Fatalf("preflight: %v", err)
	}
	saved, err := store.Load()
	if err != nil || saved.TUN || a.core.Status().TUN {
		t.Fatal("conflict changed TUN state")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(after) != string(base) {
		t.Fatal("conflict changed source")
	}
}
