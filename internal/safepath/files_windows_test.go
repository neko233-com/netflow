//go:build windows

package safepath

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestManagedOperationsRejectJunctionEscape(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "profile.yaml")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+filepath.Join(root, "profiles"), "NETFLOW_TEST_TARGET="+outside)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", out, err)
	}
	name := filepath.Join("profiles", "profile.yaml")
	if _, err := ReadFile(root, name); err == nil {
		t.Fatal("read followed junction")
	}
	if err := WriteFile(root, name, []byte("changed")); err == nil {
		t.Fatal("write followed junction")
	}
	if _, err := CreateExclusive(root, filepath.Join("profiles", "new.yaml"), []byte("new"), true); err == nil {
		t.Fatal("create followed junction")
	}
	if _, err := PrepareRemoval(root, name); err == nil {
		t.Fatal("remove followed junction")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "outside" {
		t.Fatal("outside file changed")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.yaml")); !os.IsNotExist(err) {
		t.Fatal("outside file created")
	}
}
