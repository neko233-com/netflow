package coreipc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotCopiesUserFilesAndExcludesRuntimeSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "agent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"config.yaml":         "rules: []\n",
		"cache.db":            "locked-cache",
		"agent/endpoint.json": "secret-token",
		"providers/a.yaml":    "proxies: []\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := snapshotDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[filepath.ToSlash(f.Path)] = string(f.Data)
	}
	if len(got) != 2 || got["config.yaml"] != "rules: []\n" || got["providers/a.yaml"] != "proxies: []\n" {
		t.Fatalf("unexpected snapshot: %v", got)
	}
}
