//go:build windows

package coreipc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageRejectsTraversalBeforeWritingAndUpdatesFiles(t *testing.T) {
	dir := t.TempDir()
	s := &windowsStage{dir: dir}
	if err := s.Apply([]StageFile{{Path: "valid.txt", Data: []byte("x")}, {Path: `..\outside`, Data: []byte("x")}}); err == nil {
		t.Fatal("accepted traversal")
	}
	if _, err := os.Stat(filepath.Join(dir, "valid.txt")); !os.IsNotExist(err) {
		t.Fatal("wrote a partial invalid snapshot")
	}
	if err := s.Apply([]StageFile{{Path: `providers\a.yaml`, Data: []byte("first")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply([]StageFile{{Path: `providers\a.yaml`, Data: []byte("second")}}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "providers", "a.yaml"))
	if err != nil || string(got) != "second" {
		t.Fatalf("stage update: %q %v", got, err)
	}
	if err := s.Apply([]StageFile{{Path: "A", Data: []byte("1")}, {Path: "a", Data: []byte("2")}}); err == nil {
		t.Fatal("accepted case-colliding paths")
	}
	if err := s.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "providers", "a.yaml")); !os.IsNotExist(err) {
		t.Fatalf("deleted source file remained staged: %v", err)
	}
}
