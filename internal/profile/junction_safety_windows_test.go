//go:build windows

package profile

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProfileStoreRejectsJunctionForImportDeleteAndRollback(t *testing.T) {
	base := t.TempDir()
	dir, outside := filepath.Join(base, "config"), filepath.Join(base, "outside")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(outside, "external.yaml")
	if err := os.WriteFile(file, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+filepath.Join(dir, "profiles"), "NETFLOW_TEST_TARGET="+outside)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
	store := NewStore(dir)
	initial := File{Current: "active", Items: []CatalogItem{{UID: "active", File: filepath.Join("profiles", "active.yaml")}, {UID: "other", File: filepath.Join("profiles", "external.yaml")}}}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportLocal("new.yaml", []byte("rules: []")); err == nil {
		t.Fatal("import followed junction")
	}
	if err := store.Delete("other"); err == nil {
		t.Fatal("delete followed junction")
	}
	current, err := store.Load()
	if err != nil || len(current.Items) != 2 {
		t.Fatal("failed deletion changed catalog")
	}
	one := File{Current: "only", Items: []CatalogItem{{UID: "only", File: filepath.Join("profiles", "external.yaml")}}}
	if err := store.Save(one); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardFirstImport("only"); err == nil {
		t.Fatal("rollback followed junction")
	}
	current, err = store.Load()
	if err != nil || len(current.Items) != 1 || current.Current != "only" {
		t.Fatal("failed rollback changed catalog")
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "outside" {
		t.Fatal("outside file changed")
	}
}
