package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

// TestTUNSwitchWithoutServiceLeavesProxy opens the settings switch with no
// TUN helper. The switch stays off, the notice is shown, config.yaml does
// not gain tun.enable true, a reloaded settings store is still off, and the
// system-proxy switch is left as it was. The kernel is not started.
func TestTUNSwitchWithoutServiceLeavesProxy(t *testing.T) {
	dir := t.TempDir()
	const before = "mode: rule\ntun:\n  enable: false\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	proxy := &fakeProxy{cur: sysproxy.Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}}
	blocked := &fakeTUN{unavailable: true}
	store := appconfig.NewMemory(dir)
	if err := store.Save(appconfig.Settings{SystemProxy: true}); err != nil {
		t.Fatal(err)
	}
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: store,
		Proxy: proxy,
		TUN:   blocked,
		Core:  core.New(),
	})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{ConfigDir: dir, SystemProxy: true})
	a.model.Home.TUNAvailable = false
	a.settings.SystemProxy = true
	a.bindHooks()
	a.model.Router.Replace("/settings")

	tt := newPageTester(a.model)
	if err := tt.Click("tun-row"); err != nil {
		t.Fatal(err)
	}
	if a.model.Home.TUN || blocked.on {
		t.Fatalf("tun on model %v controller %v", a.model.Home.TUN, blocked.on)
	}
	if !tt.HasText("TUN 暂不可用：需要特权服务或管理员权限") {
		t.Fatalf("notice %q texts %q", a.model.Notice, tt.Texts())
	}
	if !a.model.Home.SystemProxy {
		t.Fatal("system proxy switch flipped off")
	}

	// The switch returns before the hook. The app path must also refuse
	// and must not flip the proxy that was already on.
	if err := a.SetTUN(true); err == nil || err.Error() != tun.ErrNeedService.Error() {
		t.Fatalf("SetTUN %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != before || strings.Contains(string(body), "enable: true") {
		t.Fatalf("config changed:\n%s", body)
	}
	if !proxy.cur.Enabled {
		t.Fatal("system proxy controller was turned off")
	}
	got, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.TUN || !got.SystemProxy {
		t.Fatalf("reloaded settings %+v", got)
	}
	if a.model.Home.TUN || !a.model.Home.SystemProxy {
		t.Fatalf("model tun %v proxy %v", a.model.Home.TUN, a.model.Home.SystemProxy)
	}
}
