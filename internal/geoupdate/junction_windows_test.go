//go:build windows

package geoupdate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareAndApplyThroughJunctionRoot(t *testing.T) {
	base := t.TempDir()
	real, alias := filepath.Join(base, "real"), filepath.Join(base, "alias")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+alias, "NETFLOW_TEST_TARGET="+real)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
	write(t, real, "Country.mmdb", []byte("old"))
	if n, err := prepare(context.Background(), alias, []byte("{}"), response(fixture(t))); n != 1 || err != nil {
		t.Fatalf("prepare: %d %v", n, err)
	}
	if n, err := ApplyPending(alias); n != 1 || err != nil {
		t.Fatalf("apply: %d %v", n, err)
	}
}
