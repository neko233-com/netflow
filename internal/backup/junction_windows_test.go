//go:build windows

package backup

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestExportRejectsJunctionEscape(t *testing.T) {
	base := t.TempDir()
	source, outside := filepath.Join(base, "source"), filepath.Join(base, "outside")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, outside, "private.txt", "private")
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+filepath.Join(source, "link"), "NETFLOW_TEST_TARGET="+outside)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
	archive := filepath.Join(base, "backup.zip")
	if _, err := Export(source, archive); err == nil {
		t.Fatal("junction escape was accepted")
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatal("failed export left an archive")
	}
}
