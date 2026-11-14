package backup

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, base, name, data string) {
	t.Helper()
	file := filepath.Join(base, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineSnapshotRoundTrip(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	put(t, source, "settings.json", `{"prefs":"state"}`)
	put(t, source, "profiles/p.yaml", "rules: [MATCH,DIRECT]")
	put(t, source, "verge-imports/original.zip", "private import")
	put(t, source, "agent/endpoint.json", "secret endpoint")
	put(t, source, ".netflow.lock", "runtime lock")
	archive := filepath.Join(base, "backup.zip")
	manifest, err := Export(source, archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 3 || !strings.Contains(manifest.Warning, "private") {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if _, err := Export(source, archive); err == nil {
		t.Fatal("overwrote existing backup")
	}
	if _, err := Export(source, filepath.Join(source, "bad.zip")); err == nil {
		t.Fatal("backup allowed inside source")
	}
	target := filepath.Join(base, "restore")
	if _, err := Restore(archive, target); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, data string }{{"settings.json", `{"prefs":"state"}`}, {"profiles/p.yaml", "rules: [MATCH,DIRECT]"}, {"verge-imports/original.zip", "private import"}} {
		data, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(item.name)))
		if err != nil || string(data) != item.data {
			t.Fatalf("restore %s: %v", item.name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "agent")); !os.IsNotExist(err) {
		t.Fatal("runtime credentials restored")
	}
	if _, err := Restore(archive, target); err == nil {
		t.Fatal("overwrote existing directory")
	}
}

func writeArchive(t *testing.T, dest string, files map[string]string, m Manifest) {
	t.Helper()
	f, err := os.Create(dest)
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
	w, err := z.Create(manifestName)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreRejectsCorruptionAndUnsafePathsBeforeCreatingDirectory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		entries []Entry
	}{
		{"traversal", map[string]string{"files/../escape": "x"}, []Entry{{Path: "../escape", Size: 1, SHA256: strings.Repeat("0", 64)}}},
		{"bad_hash", map[string]string{"files/config.yaml": "x"}, []Entry{{Path: "config.yaml", Size: 1, SHA256: strings.Repeat("0", 64)}}},
		{"runtime_endpoint", map[string]string{"files/agent/endpoint.json": "x"}, []Entry{{Path: "agent/endpoint.json", Size: 1, SHA256: strings.Repeat("0", 64)}}},
		{"windows_device", map[string]string{"files/CON.txt": "x"}, []Entry{{Path: "CON.txt", Size: 1, SHA256: strings.Repeat("0", 64)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			archive, target := filepath.Join(base, "bad.zip"), filepath.Join(base, "target")
			writeArchive(t, archive, tc.files, Manifest{Format: 1, Files: tc.entries})
			if _, err := Restore(archive, target); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("invalid archive created destination")
			}
		})
	}
}

func TestPathIndexRejectsCrossPlatformCollisions(t *testing.T) {
	for _, names := range [][]string{{"Profiles/a", "profiles/b"}, {"a/b", "a"}, {"A", "a"}} {
		var index pathIndex
		if err := index.add(names[0], true); err != nil {
			t.Fatal(err)
		}
		if err := index.add(names[1], true); err == nil {
			t.Fatalf("accepted collision %v", names)
		}
	}
}

func TestPortableDeviceNames(t *testing.T) {
	for _, name := range []string{"CON.txt", "foo/COM¹.yaml", "LPT3", "CONOUT$"} {
		if validName(name) {
			t.Fatalf("accepted device name %q", name)
		}
	}
	for _, name := range []string{"COM12.txt", "profiles/example.yaml"} {
		if !validName(name) {
			t.Fatalf("rejected ordinary name %q", name)
		}
	}
}
