package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportDoesNotOverwriteOrphanedProfileFile(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(managed, 0700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(managed, "p1.yaml")
	if err := os.WriteFile(orphan, []byte("user data"), 0600); err != nil {
		t.Fatal(err)
	}
	item, err := NewStore(dir).ImportLocal("example.yaml", []byte("rules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if item.UID == "p1" {
		t.Fatal("import reused an existing profile file")
	}
	body, err := os.ReadFile(orphan)
	if err != nil || string(body) != "user data" {
		t.Fatal("orphaned file was overwritten")
	}
}
