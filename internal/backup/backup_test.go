package backup

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	put(t, source, "backup-schedule.json", "schedule must not be restored")
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledTarget := filepath.Join(base, "canceled-restore")
	if _, err := RestoreContext(ctx, archive, canceledTarget); err == nil {
		t.Fatal("canceled restore succeeded")
	}
	if _, err := os.Stat(canceledTarget); !os.IsNotExist(err) {
		t.Fatal("canceled restore created a destination")
	}
	insideTarget := filepath.Join(source, "restore-inside")
	if _, err := RestoreOutside(context.Background(), archive, insideTarget, source); err == nil {
		t.Fatal("restore was allowed inside the active configuration")
	}
	if _, err := os.Stat(insideTarget); !os.IsNotExist(err) {
		t.Fatal("rejected restore created a destination")
	}
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
	if _, err := os.Stat(filepath.Join(target, "backup-schedule.json")); !os.IsNotExist(err) {
		t.Fatal("automatic schedule restored")
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
		{"automatic_schedule", map[string]string{"files/backup-schedule.json": "x"}, []Entry{{Path: "backup-schedule.json", Size: 1, SHA256: "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}}},
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

func TestRestoreRejectsOversizedZipDirectoryBeforeExtraction(t *testing.T) {
	base := t.TempDir()
	archive := filepath.Join(base, "too-many.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := 0; i < maxFiles+2; i++ {
		if _, err := zw.Create(fmt.Sprintf("files/%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if _, err := Restore(archive, target); err == nil {
		t.Fatal("oversized ZIP directory was accepted")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("invalid archive created a destination")
	}
}

func TestPathIndexRejectsCrossPlatformCollisions(t *testing.T) {
	for _, names := range [][]string{{"Profiles/a", "profiles/b"}, {"a/b", "a"}, {"A", "a"}, {"K.yaml", "K.yaml"}} {
		var index pathIndex
		if err := index.add(names[0], true); err != nil {
			t.Fatal(err)
		}
		if err := index.add(names[1], true); err == nil {
			t.Fatalf("accepted collision %v", names)
		}
	}
}

func TestRunningSnapshotExcludesVolatileFilesAndChecksContent(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	put(t, dir, "profiles/p.yaml", "aaaa")
	put(t, dir, "cache.db", "cache")
	put(t, dir, "cache.db-wal", "wal")
	put(t, dir, "logs/current.log", "logs")
	put(t, dir, ".netflow-geodata-pending/manifest.json", "pending")
	put(t, dir, "profiles/.netflow-tmp-fixture", "temporary")
	archive := filepath.Join(base, "running.zip")
	manifest, err := ExportRunning(context.Background(), dir, archive)
	if err != nil || len(manifest.Files) != 1 || manifest.Files[0].Path != "profiles/p.yaml" {
		t.Fatalf("running snapshot: %+v %v", manifest, err)
	}
	if !strings.Contains(manifest.Warning, "excluded") {
		t.Fatal("omitted runtime data was not reported")
	}
	target := filepath.Join(base, "restored")
	if restored, err := Restore(archive, target); err != nil {
		t.Fatal(err)
	} else if restored.Warning != runningWarning {
		t.Fatal("running backup omissions were not reported at restore")
	}
	if data, err := os.ReadFile(filepath.Join(target, "profiles", "p.yaml")); err != nil || string(data) != "aaaa" {
		t.Fatal("running snapshot did not restore profile")
	}
	if _, err := os.Stat(filepath.Join(target, "cache.db")); !os.IsNotExist(err) {
		t.Fatal("runtime cache was restored")
	}
	sources, err := scanSources(context.Background(), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	digest := sha256.Sum256([]byte("aaaa"))
	entries := []Entry{{Path: "profiles/p.yaml", Size: 4, SHA256: hex.EncodeToString(digest[:])}}
	file := filepath.Join(dir, "profiles", "p.yaml")
	if err := os.WriteFile(file, []byte("bbbb"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, sources[0].info.ModTime(), sources[0].info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := verifySourceHashes(context.Background(), root, sources, entries); err == nil {
		t.Fatal("same-size change with restored timestamp was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := filepath.Join(base, "canceled.zip")
	if _, err := ExportRunning(ctx, dir, canceled); err == nil {
		t.Fatal("canceled snapshot succeeded")
	}
	if _, err := os.Stat(canceled); !os.IsNotExist(err) {
		t.Fatal("canceled snapshot left an archive")
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
