package migration

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
)

func TestImportVergeFileProvidersFromDirectoryAndBackup(t *testing.T) {
	files := map[string]string{
		"profiles.yaml":   "current: p\nitems:\n  - {uid: p, type: remote, file: p.yaml, option: {merge: m}}\n  - {uid: m, type: merge, file: m.yaml}\n",
		"profiles/p.yaml": "rules: ['RULE-SET,local,REJECT', 'MATCH,DIRECT']\n",
		"profiles/m.yaml": "defaults: &provider {type: file, behavior: domain, format: yaml}\nrule-providers:\n  local: {<<: *provider, path: ./sets/rules.yaml}\n  missing: {<<: *provider, path: ../outside.yaml}\n  remote: {type: http, behavior: domain, format: yaml, path: ./sets/cache.yaml, url: 'https://example.test/rules', interval: 86400}\n",
		"sets/rules.yaml": "payload: ['+.imported.test']\n",
	}
	for _, kind := range []string{"directory", "zip"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			source := filepath.Join(base, "source")
			if kind == "directory" {
				for name, body := range files {
					file := filepath.Join(source, filepath.FromSlash(name))
					if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(file, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(base, "outside.yaml"), []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				source += ".zip"
				f, err := os.Create(source)
				if err != nil {
					t.Fatal(err)
				}
				z := zip.NewWriter(f)
				for name, body := range files {
					w, err := z.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write([]byte(body)); err != nil {
						t.Fatal(err)
					}
				}
				if err := z.Close(); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			s, err := ReadVerge(source)
			if err != nil {
				t.Fatal(err)
			}
			warnings := strings.Join(s.Preview().Warnings, "|")
			if !strings.Contains(warnings, "外部文件未迁入") || !strings.Contains(warnings, "缓存未迁入") {
				t.Fatalf("missing warnings: %s", warnings)
			}
			target := filepath.Join(base, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ImportVerge(target); err != nil {
				t.Fatal(err)
			}
			catalog, err := profile.NewStore(target).Load()
			if err != nil {
				t.Fatal(err)
			}
			paths := catalog.Items[0].Option.VergeProviderPaths
			if paths["../outside.yaml"] == "" || paths["./sets/cache.yaml"] == "" {
				t.Fatalf("unsafe or missing mapping: %+v", paths)
			}
			if _, err := os.Stat(filepath.Join(target, filepath.FromSlash(paths["../outside.yaml"]))); !os.IsNotExist(err) {
				t.Fatal("outside source was copied")
			}
			data, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(paths["./sets/rules.yaml"])))
			if err != nil || string(data) != files["sets/rules.yaml"] {
				t.Fatalf("provider mismatch: %s %v", data, err)
			}
			body, _, _, err := ComposeArchived(target, catalog.Items[0].Option.VergeArchive, "p", []byte(files["profiles/p.yaml"]))
			if err != nil {
				t.Fatal(err)
			}
			body, err = profile.RemapVergeProviders(body, paths)
			if err != nil || !strings.Contains(string(body), paths["./sets/rules.yaml"]) || strings.Contains(string(body), "../outside.yaml") {
				t.Fatalf("bad remapping: %s %v", body, err)
			}
		})
	}
}
