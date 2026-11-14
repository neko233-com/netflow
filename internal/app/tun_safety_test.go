package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/listener"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
)

func TestUnavailableTUNCannotBeEnabledBySubscription(t *testing.T) {
	var err error
	dir := t.TempDir()
	port := freePort(t)
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns:\n  enable: false\ntun:\n  enable: true\n  auto-route: true\nrules:\n  - MATCH,DIRECT\n", port))
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	store := appconfig.NewMemory(dir)
	if err = store.Save(appconfig.Settings{TUN: true}); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: sysproxy.NewMemory(), TUN: &fakeTUN{unavailable: true}, Core: core.New()})
	if err = a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running || listener.GetTunConf().Enable || a.Home().TUN {
		t.Fatalf("unavailable TUN active: %+v %+v", a.core.Status(), a.Home())
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(base) {
		t.Fatal("subscription configuration was modified")
	}
	saved, err := store.Load()
	if err != nil || saved.TUN {
		t.Fatalf("unavailable TUN still saved: %+v %v", saved, err)
	}
}
