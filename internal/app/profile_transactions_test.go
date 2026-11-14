package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileSwitchRejectsConcurrentSourceChange(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	if err := a.importURLData("https://first.invalid/sub", []byte("mode: rule\nrules: ['MATCH,DIRECT']\n"), nil); err != nil {
		t.Fatal(err)
	}
	if err := a.importURLData("https://second.invalid/sub", []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil || len(catalog.Items) != 2 {
		t.Fatal("missing imported profiles", err)
	}
	first, second := catalog.Current, catalog.Items[1]
	oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("mode: global\nrules: ['MATCH,DIRECT']\n")
	modified := false
	engine := &switchTestEngine{running: true, dir: dir, id: first}
	engine.onReload = func() {
		if !modified {
			modified = true
			if err := os.WriteFile(filepath.Join(dir, second.File), changed, 0600); err != nil {
				t.Error(err)
			}
		}
	}
	a.core = engine
	if err := a.UseProfile(second.UID); err == nil {
		t.Fatal("accepted a changed profile during switch")
	}
	current, err := a.profiles.Load()
	config, configErr := os.ReadFile(filepath.Join(dir, "config.yaml"))
	file, fileErr := os.ReadFile(filepath.Join(dir, second.File))
	if err != nil || current.Current != first || configErr != nil || string(config) != string(oldConfig) || fileErr != nil || string(file) != string(changed) {
		t.Fatal("switch rollback lost the external change or previous configuration")
	}
}

type failingDNSReloadEngine struct {
	*switchTestEngine
	onFailure func()
}

func (e *failingDNSReloadEngine) Reload() error {
	if e.onFailure != nil {
		e.onFailure()
		e.onFailure = nil
	}
	return errors.New("synthetic reload failure")
}

func TestDNSRollbackDoesNotOverwriteConcurrentCatalogChange(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	if err := a.importURLData("https://example.invalid/sub", []byte("mode: rule\nrules: ['MATCH,DIRECT']\n"), nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	uid := catalog.Current
	engine := &failingDNSReloadEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir, id: uid}}
	engine.onFailure = func() {
		current, err := a.profiles.Load()
		if err != nil {
			t.Error(err)
			return
		}
		current.Items[0].Description = "external change"
		if err := a.profiles.Save(current); err != nil {
			t.Error(err)
		}
	}
	a.core = engine
	if err := a.setProfileDNS(uid, true, "nameserver: ['1.1.1.1']\n"); err == nil {
		t.Fatal("failed reload was accepted")
	}
	current, err := a.profiles.Load()
	if err != nil || current.Items[0].Description != "external change" {
		t.Fatal("DNS rollback overwrote concurrent catalog data")
	}
}
