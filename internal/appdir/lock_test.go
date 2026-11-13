package appdir

import (
	"errors"
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
