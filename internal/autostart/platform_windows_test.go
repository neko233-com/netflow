//go:build windows

package autostart

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsAutostartDoesNotOverwriteOtherInstall(t *testing.T) {
	key := `Software\NetFlowTests\` + filepath.Base(t.TempDir())
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, key) })
	c := &windowsController{key: key, command: func() (string, error) { return `"C:\NetFlow\NetFlow.exe"`, nil }}
	if on, err := c.Current(); err != nil || on {
		t.Fatalf("initial: %v %v", on, err)
	}
	if err := c.Set(true); err != nil {
		t.Fatal(err)
	}
	if on, err := c.Current(); err != nil || !on {
		t.Fatalf("enabled: %v %v", on, err)
	}
	other := &windowsController{key: key, command: func() (string, error) { return `"D:\Other\NetFlow.exe"`, nil }}
	if err := other.Set(false); err == nil {
		t.Fatal("removed another installation's startup item")
	}
	if err := other.Set(true); err == nil {
		t.Fatal("overwrote another installation's startup item")
	}
	if err := c.Set(false); err != nil {
		t.Fatal(err)
	}
	if on, err := c.Current(); err != nil || on {
		t.Fatalf("disabled: %v %v", on, err)
	}
}
