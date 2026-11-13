package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileFilePathRejectsEscapes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profiles", "one.yaml")
	outside := filepath.Join(dir, "outside.yaml")
	for _, path := range []string{profile, outside} {
		if err := os.WriteFile(path, []byte("rules: []"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := profileFilePath(dir, filepath.Join("profiles", "one.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := profileFilePath(dir, "outside.yaml"); err == nil {
		t.Fatal("accepted outside file")
	}
	link := filepath.Join(dir, "profiles", "escape.yaml")
	if err := os.Symlink(outside, link); err == nil {
		if _, err := profileFilePath(dir, filepath.Join("profiles", "escape.yaml")); err == nil {
			t.Fatal("accepted symlink escape")
		}
	}
}
