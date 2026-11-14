//go:build windows

package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestFailedProfileRemovalRestoresExactCatalog(t *testing.T) {
	for _, rollbackImport := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "discard_import"}[rollbackImport], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"active.yaml", "target.yaml"} {
				if err := os.WriteFile(filepath.Join(dir, "profiles", name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			current := "active"
			if rollbackImport {
				current = "target"
			}
			original := []byte(`{"items":[{"uid":"active","file":"profiles/active.yaml"},{"uid":"target","file":"profiles/target.yaml"}],"current":"` + current + `","future":{"preserve":true}}`)
			if err := os.WriteFile(filepath.Join(dir, "profiles.json"), original, 0600); err != nil {
				t.Fatal(err)
			}
			path, err := windows.UTF16PtrFromString(filepath.Join(dir, "profiles", "target.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			store := NewStore(dir)
			if rollbackImport {
				err = store.DiscardFirstImport("target")
			} else {
				err = store.Delete("target")
			}
			if err == nil {
				t.Fatal("removal unexpectedly succeeded while deletion was denied")
			}
			actual, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("failed removal did not restore exact catalog bytes")
			}
			if body, err := os.ReadFile(filepath.Join(dir, "profiles", "target.yaml")); err != nil || string(body) != "target.yaml" {
				t.Fatal("failed removal lost profile data")
			}
		})
	}
}
