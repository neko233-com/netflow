package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestLocalProfileImportAndDelete(t *testing.T) {
	dir := t.TempDir()
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{})
	for _, name := range []string{"one.yaml", "two.yaml"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("rules:\n  - MATCH,DIRECT\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := a.ImportLocal(path); err != nil {
			t.Fatal(err)
		}
	}
	f, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Items) != 2 || f.Current != f.Items[0].UID {
		t.Fatalf("catalog: %+v", f)
	}
	if err := a.DeleteProfile(f.Current); err == nil {
		t.Fatal("deleted active profile")
	}
	path := filepath.Join(dir, f.Items[1].File)
	if err := a.DeleteProfile(f.Items[1].UID); err != nil {
		t.Fatal(err)
	}
	f, err = a.profiles.Load()
	if err != nil || len(f.Items) != 1 {
		t.Fatalf("catalog: %+v, %v", f, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("managed file not removed: %v", err)
	}
}

func TestSwitchRejectsInvalidProfileWithoutChangingCurrent(t *testing.T) {
	dir := t.TempDir()
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{})
	a.profiles = profile.NewStore(dir)
	good, err := a.profiles.ImportLocal("good.yaml", []byte("rules:\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := a.profiles.ImportLocal("bad.yaml", []byte("proxies: [broken"))
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("mode: rule\nrules:\n  - MATCH,DIRECT\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.UseProfile(bad.UID); err == nil {
		t.Fatal("invalid profile activated")
	}
	got, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(got) != string(old) {
		t.Fatalf("running config changed: %q %v", got, err)
	}
	f, err := a.profiles.Load()
	if err != nil || f.Current != good.UID {
		t.Fatalf("current profile changed: %+v %v", f, err)
	}
}

func TestLocalProfileRejectsInvalidDocument(t *testing.T) {
	dir := t.TempDir()
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
	a.dir = dir
	a.model = ui.NewModel(ui.HomeState{})
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.ImportLocal(path); err == nil {
		t.Fatal("invalid YAML accepted")
	}
	f, err := a.profiles.Load()
	if err != nil || len(f.Items) != 0 {
		t.Fatalf("invalid file persisted: %+v %v", f, err)
	}
}
