package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestImportTransactionPreservesCurrentAndRollsBackFirstActivation(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: direct\nlog-level: error\nipv6: false\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", port))
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "source.yaml")
	if err = os.WriteFile(file, base, 0600); err != nil {
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
	failed := false
	a.core.SetTransformer(func(data []byte, _ string) ([]byte, error) {
		if !failed {
			failed = true
			return nil, errors.New("injected reload failure")
		}
		return data, nil
	})
	if err = a.ImportLocal(file); err == nil {
		t.Fatal("failed activation reported success")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Items) != 0 || catalog.Current != "" {
		t.Fatalf("failed import remains in catalog: %+v", catalog)
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(base) || a.core.ProfileID() != "" {
		t.Fatal("failed import did not restore active configuration")
	}
	if err = a.ImportLocal(file); err != nil {
		t.Fatal(err)
	}
	a.core.SetTransformer(func(data []byte, _ string) ([]byte, error) {
		return kernelopts.Compose(data, a.kernelOptions.Snapshot())
	})
	if err = a.SetMode("rule"); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(path)
	calls := 0
	a.core.SetTransformer(func(data []byte, _ string) ([]byte, error) { calls++; return data, nil })
	if err = a.ImportLocal(file); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if calls != 0 || string(after) != string(current) || a.core.Status().Mode != "rule" {
		t.Fatal("importing inactive profile reset active mode or reloaded core")
	}
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	otherPort := other.Addr().(*net.TCPAddr).Port
	_ = other.Close()
	otherConfig := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", otherPort))
	otherFile := filepath.Join(dir, "other.yaml")
	if err = os.WriteFile(otherFile, otherConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.ImportLocal(otherFile); err != nil {
		t.Fatal(err)
	}
	catalog, err = a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	target := catalog.Items[len(catalog.Items)-1].UID
	a.settings.SystemProxy = true
	if err = a.UseProfile(target); err == nil {
		t.Fatal("switched system proxy to a stale endpoint")
	}
	after, _ = os.ReadFile(path)
	if string(after) != string(current) || a.core.ProfileID() == target {
		t.Fatal("blocked switch changed active state")
	}
}
