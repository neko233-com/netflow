package appdir

import (
	"path/filepath"
	"testing"
)

func TestPath(t *testing.T) {
	home := "/Users/me"
	if got, want := Path(home, "darwin"), filepath.Join(home, "Library", "Application Support", SupportDirName); got != want {
		t.Fatalf("darwin path %q, want %q", got, want)
	}
	if got, want := Path(home, "linux"), filepath.Join(home, ".config", SupportDirName); got != want {
		t.Fatalf("linux path %q, want %q", got, want)
	}
	if got, want := Path(home, "windows"), filepath.Join(home, "AppData", "Roaming", SupportDirName); got != want {
		t.Fatalf("windows path %q, want %q", got, want)
	}
}

func TestFixed(t *testing.T) {
	if _, err := Fixed("").ConfigDir(); err == nil {
		t.Fatal("empty Fixed returned a directory")
	}
	got, err := Fixed("/tmp/clash-go").ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/clash-go" {
		t.Fatalf("got %q", got)
	}
}
