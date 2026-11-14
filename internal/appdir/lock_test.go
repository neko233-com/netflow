package appdir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLockPreventsConcurrentWritersAndReleases(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Acquire(dir); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second lock: %v", err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigLockRejectsExternalHardLink(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, ".netflow.lock")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if lock, err := Acquire(dir); err == nil {
		lock.Close()
		t.Fatal("hard-linked lock was accepted")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "external" {
		t.Fatal("external file changed")
	}
}
