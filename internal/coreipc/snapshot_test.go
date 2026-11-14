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
	if err := os.Mkdir(filepath.Join(dir, "verge-imports"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "verge-script-outputs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "profiles", ".netflow-script-subscriptions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".netflow-geodata-pending"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"config.yaml":         "rules: []\n",
		"cache.db":            "locked-cache",
		"agent/endpoint.json": "secret-token",
		"providers/a.yaml":    "proxies: []\n",
		"profiles.json":       "subscription credentials",
		"settings.json":       "desktop settings",
		"kernel-options.json": "desktop options",
		"agent-rules.json":    "desktop rules",
		"verge-imports/v0123456789abcdef0123456789abcdef.zip": "private recovery archive",
		"verge-imports/user.yaml":                             "arbitrary user file",
		"verge-script-outputs/private.json":                   "private approved output",
		"profiles/.netflow-script-subscriptions/old.yaml":     "private rollback subscription",
		".netflow-geodata-pending/manifest.json":              "desktop transaction",
		".netflow-geodata-tmp-abandoned":                      "unfinished update",
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
	if len(got) != 3 || got["config.yaml"] != "rules: []\n" || got["providers/a.yaml"] != "proxies: []\n" || got["verge-imports/user.yaml"] != "arbitrary user file" {
		t.Fatalf("unexpected snapshot: %v", got)
	}
}

func TestRecoveryArchiveNameIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"verge-imports/v0123456789abcdef0123456789abcdef.zip", true},
		{"verge-imports/v0123456789abcdef0123456789abcdeg.zip", false},
		{"verge-imports/user.zip", false},
		{"other/v0123456789abcdef0123456789abcdef.zip", false},
	} {
		if got := isVergeRecoveryArchive(filepath.FromSlash(tc.name)); got != tc.want {
			t.Fatalf("%s: %v", tc.name, got)
		}
	}
}
