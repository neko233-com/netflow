//go:build windows

package validation

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHashSourceSupportsCanonicalPathForJunctionRoot(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "actual")
	alias := filepath.Join(parent, "alias")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+alias, "NETFLOW_TEST_TARGET="+real)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
	if err := os.WriteFile(filepath.Join(real, "file.yaml"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := HashSource(root, alias, filepath.Join(real, "file.yaml")); err != nil {
		t.Fatalf("canonical path was rejected: %v", err)
	}
	name, err := windows.UTF16PtrFromString(real)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err == nil && n > 0 && int(n) < len(buffer) {
		short := windows.UTF16ToString(buffer[:n])
		shortRoot, err := os.OpenRoot(short)
		if err != nil {
			t.Fatal(err)
		}
		_, err = HashSource(shortRoot, short, filepath.Join(real, "file.yaml"))
		_ = shortRoot.Close()
		if err != nil {
			t.Fatalf("short path root rejected: %v", err)
		}
	}
	if _, err := HashSource(root, alias, filepath.Join(real, "missing.yaml")); !os.IsNotExist(err) {
		t.Fatalf("missing canonical source was not reported: %v", err)
	}
	if _, err := HashSource(root, alias, filepath.Join(parent, "outside")); err == nil {
		t.Fatal("outside source accepted")
	}
}
