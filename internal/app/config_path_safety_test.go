package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetModeDoesNotModifyHardLinkedExternalFile(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.yaml")
	const original = "mode: rule\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(outside, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, "config.yaml")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	a := &App{dir: dir}
	if err := a.SetMode("global"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != original {
		t.Fatal("external hard-linked file was modified")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "config.yaml")); err != nil || !strings.Contains(string(data), "global") {
		t.Fatal("managed config was not updated")
	}
}
