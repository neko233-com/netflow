package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunningFingerprintMatchesArchiveAndDetectsMetadataPreservingEdit(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	put(t, dir, "settings.json", "first")
	put(t, dir, "logs/runtime.log", "ignored")
	manifest, err := ExportRunning(context.Background(), dir, filepath.Join(base, "backup.zip"))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ManifestFingerprint(manifest)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := RunningFingerprint(context.Background(), dir)
	if err != nil || actual != expected {
		t.Fatalf("archive fingerprint mismatch: %s %s %v", actual, expected, err)
	}
	before, err := RunningInventory(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "settings.json")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := RunningInventory(context.Background(), dir)
	if err != nil || after != before {
		t.Fatalf("inventory should be a metadata hint: %v", err)
	}
	changed, err := RunningFingerprint(context.Background(), dir)
	if err != nil || changed == actual {
		t.Fatalf("content change was not detected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunningFingerprint(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fingerprint: %v", err)
	}
	if _, err := RunningInventory(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inventory: %v", err)
	}
}
