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
	"github.com/neko233-com/netflow/internal/service"
	"github.com/neko233-com/netflow/internal/sitetest"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

type fakeProxy struct {
	cur    sysproxy.Settings
	setErr error
}

func (f *fakeProxy) Current() (sysproxy.Settings, error) { return f.cur, nil }

func (f *fakeProxy) Set(s sysproxy.Settings) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.cur = s
	return nil
}

type fakeTUN struct {
	on          bool
	setErr      error
	unavailable bool
}

func (f *fakeTUN) Current() (bool, error) { return f.on, nil }

func (f *fakeTUN) Available() bool { return f == nil || !f.unavailable }

func (f *fakeTUN) Set(on bool) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.on = on
	return nil
}

func TestSetSystemProxyUsesController(t *testing.T) {
	dir := t.TempDir()
	proxy := &fakeProxy{}
	store := appconfig.NewMemory(dir)
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: store,
		Proxy: proxy,
		TUN:   tun.NewMemory(),
		Core:  core.New(),
	})
	if err := a.SetSystemProxy(true); err != nil {
		t.Fatal(err)
	}
	if !proxy.cur.Enabled || proxy.cur.HTTP != "127.0.0.1:7897" || proxy.cur.SOCKS != "127.0.0.1:7897" {
		t.Fatalf("proxy %+v", proxy.cur)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.SystemProxy || got.TUN {
		t.Fatalf("settings %+v", got)
	}

	proxy.setErr = errors.New("denied")
	if err := a.SetSystemProxy(false); err == nil {
		t.Fatal("SetSystemProxy succeeded after the controller failed")
	}
	got, _ = store.Load()
	if !got.SystemProxy {
		t.Fatal("failed Set cleared the saved proxy")
	}
}

func TestSetModeRewritesProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mode: rule\nmixed-port: 7897\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: appconfig.NewMemory(dir),
		Proxy: sysproxy.NewMemory(),
		TUN:   tun.NewMemory(),
		Core:  core.New(),
	})
	a.dir = dir
	if err := a.SetMode("direct"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "mode: direct") {
		t.Fatalf("config %s", body)
	}
}

func TestSetTUNRollsBack(t *testing.T) {
	dir := t.TempDir()
	store := appconfig.NewMemory(dir)
	store.FailSave(errors.New("disk"))
	tunCtl := &fakeTUN{}
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: store,
		Proxy: sysproxy.NewMemory(),
		TUN:   tunCtl,
		Core:  core.New(),
	})
	if err := a.SetTUN(true); err == nil {
		t.Fatal("SetTUN succeeded with a failing store")
	}
	if tunCtl.on {
		t.Fatal("TUN stayed on after the store failed")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.TUN {
		t.Fatal("store kept TUN")
	}
}

func TestSetTUNWritesVergeDefaultsWithoutDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("mode: rule\nmixed-port: 7897\nipv6: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mem := tun.NewMemory()
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: appconfig.NewMemory(dir),
		Proxy: sysproxy.NewMemory(),
		TUN:   mem,
		Core:  core.New(),
	})
	a.dir = dir
	if err := a.SetTUN(true); err != nil {
		t.Fatal(err)
	}
	on, err := mem.Current()
	if err != nil || !on {
		t.Fatalf("memory tun %v %v", on, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"enable: true", "mips", "auto-route: true", "any:53", "fake-ip", "198.18.0.1/16"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	if a.core.Status().Running {
		t.Fatal("writing tun config started the kernel")
	}
}

func TestSetTUNRefusesWithoutHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const before = "mode: rule\ntun:\n  enable: false\n"
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := &fakeTUN{unavailable: true}
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: appconfig.NewMemory(dir),
		Proxy: sysproxy.NewMemory(),
		TUN:   blocked,
		Core:  core.New(),
	})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{})
	if err := a.SetTUN(true); err == nil || err.Error() != tun.ErrNeedService.Error() {
		t.Fatalf("SetTUN %v", err)
	}
	if blocked.on || a.model.Home.TUN || a.model.Notice != tun.ErrNeedService.Error() {
		t.Fatalf("on %v tun %v notice %q", blocked.on, a.model.Home.TUN, a.model.Notice)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != before || strings.Contains(string(body), "enable: true") {
		t.Fatalf("config changed:\n%s", body)
	}
	got, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.TUN {
		t.Fatal("settings stored TUN")
	}
}

func TestServiceMakesTUNUsable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("mode: rule\nmixed-port: 7897\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := &service.Memory{}
	blocked := &fakeTUN{unavailable: true}
	a := New(Options{
		Dirs:    appdir.Fixed(dir),
		Store:   appconfig.NewMemory(dir),
		Proxy:   sysproxy.NewMemory(),
		TUN:     blocked,
		Service: svc,
		Core:    core.New(),
	})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{})
	if err := a.SetTUN(true); err == nil || a.model.Notice != tun.ErrNeedService.Error() {
		t.Fatalf("without service %v notice %q", err, a.model.Notice)
	}
	if err := a.InstallService(); err != nil {
		t.Fatal(err)
	}
	if !a.Model().ServiceInstalled || !a.Home().TUNAvailable {
		t.Fatalf("after install %+v", a.Home())
	}
	if err := a.SetTUN(true); err != nil {
		t.Fatal(err)
	}
	if svc.Starts != 1 || svc.Dir != dir || !a.Home().TUN {
		t.Fatalf("starts %d dir %q tun %v", svc.Starts, svc.Dir, a.Home().TUN)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "enable: true") || !strings.Contains(string(body), "mips") {
		t.Fatalf("config %s", body)
	}
	if a.core.Status().Running {
		t.Fatal("service path started mihomo in the app process")
	}
	if err := a.UninstallService(); err != nil {
		t.Fatal(err)
	}
	if svc.Installed || a.Home().TUN || a.Home().TUNAvailable {
		t.Fatalf("after uninstall home %+v installed %v", a.Home(), svc.Installed)
	}
}

func TestSitesPersistAcrossStoreReload(t *testing.T) {
	dir := t.TempDir()
	if err := sitetest.NewStore(dir).Save([]sitetest.Item{
		{UID: "g", Name: "Google", URL: "https://www.google.com", Icon: "G"},
	}); err != nil {
		t.Fatal(err)
	}
	a := newProfileHarness(dir)
	a.loadSites()
	if len(a.Model().Sites) != 1 || a.Model().Sites[0].Name != "Google" || a.Model().Sites[0].Delay != -1 {
		t.Fatalf("loaded %+v", a.Model().Sites)
	}
	a.Model().Sites = append(a.Model().Sites, ui.SiteTest{UID: "e", Name: "Example", URL: "https://example.com", Icon: "E", Delay: 12})
	if err := a.saveSites(a.Model().Sites); err != nil {
		t.Fatal(err)
	}
	again := newProfileHarness(dir)
	again.loadSites()
	got := again.Model().Sites
	if len(got) != 2 || got[1].Name != "Example" || got[1].Delay != -1 || got[1].Icon != "E" {
		t.Fatalf("reloaded %+v", got)
	}
}
