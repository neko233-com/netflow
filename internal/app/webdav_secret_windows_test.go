//go:build windows

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestLegacyWebDAVSecretMigrationPreservesOtherPreferences(t *testing.T) {
	const password = "synthetic-webdav-secret"
	const address = "https://user:synthetic-url-secret@backup.invalid/?token=synthetic-token"
	store := appconfig.NewMemory(t.TempDir())
	initial := appconfig.Settings{Prefs: `{"WebDAVURL":"https://user:synthetic-url-secret@backup.invalid/?token=synthetic-token","WebDAVUser":"synthetic-user","WebDAVPassword":"synthetic-webdav-secret","UnknownFuture":{"value":17}}`}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	settings, protected, err := a.migrateWebDAVSecret(initial)
	if err != nil || protected == "" || strings.Contains(settings.Prefs, password) || strings.Contains(settings.Prefs, "synthetic-url-secret") || strings.Contains(settings.Prefs, "synthetic-token") || strings.Contains(settings.Prefs, "synthetic-user") {
		t.Fatalf("migration failed: %v", err)
	}
	plain, err := unprotectWebDAV(protected)
	if err != nil || plain.Password != password || plain.URL != address || plain.User != "synthetic-user" {
		t.Fatalf("protected secret cannot be recovered: %v", err)
	}
	a.settings, a.webDAVProtected = settings, protected
	if recovered, err := a.savedWebDAV(); err != nil || recovered.Password != password || recovered.URL != address {
		t.Fatalf("saved credential could not be retrieved: %v", err)
	}
	prefs := ui.DefaultPrefs()
	prefs.ThemeMode = "dark"
	if err := a.savePrefs(prefs); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil || strings.Contains(saved.Prefs, password) {
		t.Fatalf("saved preference leaked secret: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(saved.Prefs), &fields); err != nil || len(fields["UnknownFuture"]) == 0 || len(fields[webDAVProtectedKey]) == 0 {
		t.Fatalf("preferences lost: %v", err)
	}
	if err := a.clearWebDAVSecret(); err != nil {
		t.Fatal(err)
	}
	saved, _ = store.Load()
	fields = nil
	if json.Unmarshal([]byte(saved.Prefs), &fields) != nil || len(fields["UnknownFuture"]) == 0 || len(fields[webDAVProtectedKey]) == 0 {
		t.Fatal("clear removed unrelated preferences or WebDAV address")
	}
	if recovered, err := a.savedWebDAV(); err != nil || recovered.Password != "" || recovered.URL != address || recovered.User != "synthetic-user" {
		t.Fatal("clear did not preserve the address and user")
	}
}

func TestPrepareMigratesLegacyCredentialBeforeShowingSettings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mixed-port: 0\nport: 0\nsocks-port: 0\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := appconfig.NewMemory(dir)
	if err := store.Save(appconfig.Settings{Prefs: `{"WebDAVPassword":"synthetic-prepare-secret"}`}); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.model.WebDAVSecretStored || a.model.Prefs.WebDAVPassword != "" || a.model.Prefs.WebDAVURL != "" || a.model.Prefs.WebDAVUser != "" {
		t.Fatal("credential was exposed to the UI model")
	}
	saved, err := store.Load()
	if err != nil || strings.Contains(saved.Prefs, "synthetic-prepare-secret") || a.webDAVProtected == "" {
		t.Fatalf("credential not protected: %v", err)
	}
	if plain, err := unprotectWebDAV(a.webDAVProtected); err != nil || plain.Password != "synthetic-prepare-secret" {
		t.Fatalf("credential not recoverable: %v", err)
	}
}

func TestLegacySecretMigrationFailureDoesNotModifySettings(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	initial := appconfig.Settings{Prefs: `{"WebDAVPassword":"synthetic-secret","Other":true}`}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	store.FailSave(errors.New("simulated write failure"))
	a := &App{store: store}
	got, protected, err := a.migrateWebDAVSecret(initial)
	if err == nil || protected != "" || got.Prefs != initial.Prefs {
		t.Fatal("failed migration changed the original settings")
	}
	store.FailSave(nil)
	saved, _ := store.Load()
	if saved.Prefs != initial.Prefs {
		t.Fatal("failed migration overwrote saved settings")
	}
	duplicate := appconfig.Settings{Prefs: `{"WebDAVPassword":"a","webdavpassword":"b"}`}
	got, _, migrationErr := a.migrateWebDAVSecret(duplicate)
	if migrationErr == nil || got.Prefs != duplicate.Prefs {
		t.Fatal("ambiguous credentials were altered")
	}
	a.settings, a.webDAVProtectionErr = duplicate, migrationErr
	if err := a.savePrefs(ui.DefaultPrefs()); err == nil {
		t.Fatal("ambiguous credentials were overwritten by another setting")
	}
	if _, err := a.savedWebDAV(); err == nil {
		t.Fatal("ambiguous credential was copied")
	}
	if err := a.clearWebDAVSecret(); err != nil {
		t.Fatal(err)
	}
	if err := a.savePrefs(ui.DefaultPrefs()); err != nil {
		t.Fatalf("explicit clearing did not unblock settings: %v", err)
	}
}

func TestDuplicateExactPreferenceKeysArePreserved(t *testing.T) {
	initial := appconfig.Settings{Prefs: `{"WebDAVPassword":"first","WebDAVPassword":"second","Other":true}`}
	store := appconfig.NewMemory(t.TempDir())
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	got, _, err := a.migrateWebDAVSecret(initial)
	if err == nil || got.Prefs != initial.Prefs {
		t.Fatal("duplicate keys must prevent migration")
	}
	a.settings, a.webDAVProtectionErr = initial, err
	if err := a.savePrefs(ui.DefaultPrefs()); err == nil {
		t.Fatal("duplicate keys must prevent preference overwrites")
	}
	saved, err := store.Load()
	if err != nil || saved.Prefs != initial.Prefs {
		t.Fatal("ambiguous preferences were altered")
	}
}
