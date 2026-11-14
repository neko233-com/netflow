package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedAtomicWritesAndConflictDetection(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, "settings.json", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimit(dir, "settings.json", 2); err == nil {
		t.Fatal("caller size limit ignored")
	}
	if err := CompareAndWrite(dir, "settings.json", []byte("wrong"), []byte("new")); !errors.Is(err, ErrChanged) {
		t.Fatalf("conflict accepted: %v", err)
	}
	if got, err := ReadFile(dir, "settings.json"); err != nil || string(got) != "old" {
		t.Fatalf("original changed: %q %v", got, err)
	}
	if err := CompareAndWrite(dir, "settings.json", []byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := CompareAndRemove(dir, "settings.json", []byte("old")); !errors.Is(err, ErrChanged) {
		t.Fatalf("wrong content removed: %v", err)
	}
	if err := CompareAndRemove(dir, "settings.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(dir, "settings.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file remains: %v", err)
	}
	if err := CompareAndWrite(dir, "settings.json", nil, []byte("created")); err != nil {
		t.Fatal(err)
	}
	if err := CompareAndWrite(dir, "settings.json", nil, []byte("overwrite")); !errors.Is(err, ErrChanged) {
		t.Fatalf("existing file overwritten: %v", err)
	}
}

func TestCreatedRollbackPreservesReplacement(t *testing.T) {
	dir := t.TempDir()
	created, err := CreateExclusive(dir, filepath.Join("profiles", "one.yaml"), []byte("original"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	file := filepath.Join(dir, "profiles", "one.yaml")
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := created.Remove(); !errors.Is(err, ErrChanged) {
		t.Fatalf("replacement removal accepted: %v", err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "replacement" {
		t.Fatal("replacement was removed")
	}
}

func TestCreatedRollbackPreservesEditedOrReplacedFile(t *testing.T) {
	dir := t.TempDir()
	created, err := CreateExclusive(dir, "created.yaml", []byte("original"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	path := filepath.Join(dir, "created.yaml")
	if err := os.WriteFile(path, []byte("edited"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := created.RemoveIfUnchanged([]byte("original")); !errors.Is(err, ErrChanged) {
		t.Fatalf("edited file removed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := created.RemoveIfUnchanged([]byte("original")); !errors.Is(err, ErrChanged) {
		t.Fatalf("replacement file removed: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "original" {
		t.Fatal("replacement was not preserved")
	}
}

func TestManagedTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../outside", ".", filepath.Join("profiles", "..", "..", "outside")} {
		if _, _, err := Parent(dir, name, true); err == nil {
			t.Fatalf("accepted path %q", name)
		}
	}
}

func TestManagedFinalSymlinkRejected(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "settings.json")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := ReadFile(root, "settings.json"); err == nil {
		t.Fatal("read followed final symlink")
	}
	if err := WriteFile(root, "settings.json", []byte("changed")); err == nil {
		t.Fatal("write followed final symlink")
	}
	if err := CompareAndRemove(root, "settings.json", []byte("outside")); err == nil {
		t.Fatal("remove followed final symlink")
	}
	if f, err := OpenLock(root, "settings.json"); err == nil {
		f.Close()
		t.Fatal("lock followed final symlink")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
		t.Fatal("outside file changed")
	}
}
