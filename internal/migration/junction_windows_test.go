//go:build windows

package migration

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func makeTestJunction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+link, "NETFLOW_TEST_TARGET="+target)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
}

func TestMigrationRejectsJunctionEscapeAndTargetInsideSource(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "profiles.yaml"), []byte("current: p\nitems: [{uid: p, type: local, file: p.yaml}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "profiles", "p.yaml"), []byte("rules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(source, "inside")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	makeTestJunction(t, alias, inside)
	if err := s.ValidateTarget(alias); err == nil {
		t.Error("target junction into source accepted")
	}
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	makeTestJunction(t, filepath.Join(target, "profiles"), filepath.Join(source, "profiles"))
	if _, err := s.ImportVerge(target); err == nil {
		t.Fatal("target profiles junction accepted")
	}
	entries, err := os.ReadDir(filepath.Join(source, "profiles"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("source profile directory changed: %v %v", entries, err)
	}
}

func TestManagedFileRejectsJunctionEscape(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(target, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	makeTestJunction(t, filepath.Join(target, "profiles", "escape"), outside)
	if _, err := managedFile(target, "profiles", filepath.Join("profiles", "escape", "secret.yaml")); err == nil {
		t.Fatal("managed file escaped through junction")
	}
}
