//go:build windows

package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestProfileFilePathWithJunctionRootAndEscape(t *testing.T) {
	parent := t.TempDir()
	real, alias, outside := filepath.Join(parent, "actual"), filepath.Join(parent, "alias"), filepath.Join(parent, "outside")
	if err := os.MkdirAll(filepath.Join(real, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(real, "profiles", "p.yaml"), filepath.Join(outside, "secret.yaml")} {
		if err := os.WriteFile(file, []byte("rules: ['MATCH,DIRECT']\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, target string) {
		cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
		cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+name, "NETFLOW_TEST_TARGET="+target)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("create junction: %s %v", output, err)
		}
	}
	link(alias, real)
	link(filepath.Join(real, "profiles", "escape"), outside)
	if _, err := profileFilePath(alias, filepath.Join("profiles", "p.yaml")); err != nil {
		t.Fatalf("valid junction root rejected: %v", err)
	}
	if _, err := profileFilePath(alias, filepath.Join("profiles", "escape", "secret.yaml")); err == nil {
		t.Fatal("profile escaped through junction")
	}
}

func TestVergePreviewFromJunctionConfigDirectory(t *testing.T) {
	base := t.TempDir()
	source, real, alias := filepath.Join(base, "source"), filepath.Join(base, "actual"), filepath.Join(base, "alias")
	if err := os.MkdirAll(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+alias, "NETFLOW_TEST_TARGET="+real)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
	files := map[string]string{
		"profiles.yaml":   "current: p\nitems:\n  - {uid: p, type: local, file: p.yaml, option: {merge: m}}\n  - {uid: m, type: merge, file: m.yaml}\n",
		"profiles/p.yaml": fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)),
		"profiles/m.yaml": "profile: {store-selected: true}\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parsed, err := migration.ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.ImportVerge(alias); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(alias), Store: appconfig.NewMemory(alias), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core failed: %s", a.model.Home.Error)
	}
	_, err = a.agentPreview(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,example.test,DIRECT"}}})
	if err != nil {
		t.Fatalf("preview failed for junction root: %v", err)
	}
}
