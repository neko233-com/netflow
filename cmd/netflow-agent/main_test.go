package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/profile"
)

func TestRealVergeImportThroughCLI(t *testing.T) {
	source := os.Getenv("NETFLOW_TEST_VERGE_SOURCE")
	if source == "" {
		t.Skip("real Verge source not configured")
	}
	target := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"--config-dir", target, "migrate-preview", source}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		Profiles []struct {
			ID string `json:"id"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || len(preview.Profiles) == 0 {
		t.Fatal("invalid CLI migration preview")
	}
	out.Reset()
	lock, err := appdir.Acquire(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"--config-dir", target, "migrate-import", source}, bytes.NewReader(nil), &out); err == nil {
		t.Fatal("import accepted while target was locked")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"--config-dir", target, "migrate-import", source}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Imported int `json:"imported"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Imported != len(preview.Profiles) {
		t.Fatal("CLI import count mismatch")
	}
	cat, err := profile.NewStore(target).Load()
	if err != nil || len(cat.Items) != result.Imported {
		t.Fatal("CLI import catalog mismatch")
	}
	for _, item := range cat.Items {
		if _, err = os.Stat(filepath.Join(target, item.File)); err != nil {
			t.Fatal("CLI import file missing")
		}
	}
}

func TestPreviewRejectsTrailingAndOversizedInputBeforeBridge(t *testing.T) {
	for _, input := range []string{`{"scope":"global","operation":"clear"} {}`, strings.Repeat(" ", (1<<20)+1)} {
		var out bytes.Buffer
		err := run([]string{"--config-dir", t.TempDir(), "preview"}, strings.NewReader(input), &out)
		if err == nil || strings.Contains(err.Error(), "bridge") {
			t.Fatalf("invalid preview input accepted: %v", err)
		}
	}
}
