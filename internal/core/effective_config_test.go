package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEffectiveConfigIsLastSuccessfulComposedSnapshot(t *testing.T) {
	dir := t.TempDir()
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nrules:\n  - MATCH,DIRECT\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.SetTransformer(func(data []byte, _ string) ([]byte, error) {
		return []byte(strings.Replace(string(data), "mode: rule", "mode: direct", 1)), nil
	})
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	snapshot, err := c.EffectiveConfig()
	if err != nil || !strings.Contains(string(snapshot), "mode: direct") {
		t.Fatalf("snapshot %q %v", snapshot, err)
	}
	snapshot[0] = 'X'
	copyAgain, err := c.EffectiveConfig()
	if err != nil || copyAgain[0] == 'X' {
		t.Fatal("caller changed stored snapshot")
	}
	c.SetTransformer(func([]byte, string) ([]byte, error) { return nil, errors.New("reload failed") })
	if err := c.Reload(); err == nil {
		t.Fatal("expected reload failure")
	}
	previous, err := c.EffectiveConfig()
	if err != nil || !strings.Contains(string(previous), "mode: direct") {
		t.Fatal("failed reload replaced snapshot")
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EffectiveConfig(); err == nil {
		t.Fatal("stopped core exposed stale snapshot")
	}
}
