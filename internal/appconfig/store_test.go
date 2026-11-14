package appconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/safepath"
)

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != (Settings{}) {
		t.Fatalf("missing file loaded %+v", got)
	}
	want := Settings{SystemProxy: true, TUN: true}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("loaded %+v, want %+v", got, want)
	}
	if s.Dir() != dir {
		t.Fatalf("dir %q", s.Dir())
	}
}

func TestFileStorePreservesUnknownFieldsAndRejectsExternalEdits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	original := []byte(`{"TUN":true,"future":{"value":7},"trayEvent":"old"}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(dir)
	settings, err := s.Load()
	if err != nil || !settings.TUN {
		t.Fatalf("load: %+v %v", settings, err)
	}
	settings.TUN, settings.TrayEvent = false, ""
	if err := s.Save(settings); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	var fields map[string]json.RawMessage
	var future map[string]int
	if err != nil || json.Unmarshal(data, &fields) != nil || json.Unmarshal(fields["future"], &future) != nil || future["value"] != 7 || fields["TUN"] != nil || fields["trayEvent"] != nil || string(fields["tun"]) != "false" {
		t.Fatalf("unknown or known fields mishandled: %s %v", data, err)
	}
	external := []byte(`{"tun":true,"future":{"external":true}}`)
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(settings); !errors.Is(err, safepath.ErrChanged) {
		t.Fatalf("external edit accepted: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(external) {
		t.Fatal("external edit overwritten")
	}
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(settings); err != nil {
		t.Fatalf("explicit reload did not recover: %v", err)
	}
}

func TestFileStoreDistinguishesMissingAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(dir)
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Settings{TUN: true}); err != nil {
		t.Fatalf("empty file was treated as missing: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Settings{}); !errors.Is(err, safepath.ErrChanged) {
		t.Fatalf("deletion was not detected: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted file was recreated")
	}
}

func TestMemoryStore(t *testing.T) {
	m := NewMemory("/cfg")
	if err := m.Save(Settings{SystemProxy: true}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.SystemProxy || got.TUN {
		t.Fatalf("loaded %+v", got)
	}
	if m.Dir() != "/cfg" {
		t.Fatalf("dir %q", m.Dir())
	}
}
