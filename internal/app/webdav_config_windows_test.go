//go:build windows

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
)

func TestWebDAVConfigSavesProtectedAndClearsWithoutLosingPreferences(t *testing.T) {
	dir := t.TempDir()
	store := appconfig.NewFileStore(dir)
	initial := appconfig.Settings{Prefs: `{"UnknownFuture":{"value":17}}`}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	a := &App{dir: dir, store: store, settings: initial}
	args := agent.WebDAVConfigArgs{URL: "https://backup.invalid/dav?token=synthetic-token", User: "synthetic-user", Password: "synthetic-password"}
	if err := a.saveWebDAVConfig(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil || strings.Contains(string(data), "synthetic-") || !strings.Contains(string(data), "UnknownFuture") {
		t.Fatal("stored settings exposed credentials or lost unrelated data")
	}
	saved, err := a.savedWebDAV()
	if err != nil || saved.URL != args.URL || saved.User != args.User || saved.Password != args.Password {
		t.Fatal("protected configuration did not round trip")
	}
	status, err := a.webDAVConfigStatus()
	if err != nil || !status.Saved || !status.ProtectedStorageAvailable {
		t.Fatal("protected configuration status was incorrect")
	}
	if err := a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: "http://unsafe.invalid"}); err == nil {
		t.Fatal("accepted insecure replacement")
	}
	if recovered, err := a.savedWebDAV(); err != nil || recovered.Password != args.Password {
		t.Fatal("invalid replacement destroyed saved configuration")
	}
	a.backupBusy = true
	if err := a.clearWebDAVConfig(); err == nil {
		t.Fatal("cleared credentials during an active backup")
	}
	if err := a.saveWebDAVConfig(args); err == nil {
		t.Fatal("replaced credentials during an active backup")
	}
	a.backupBusy = false
	if err := a.clearWebDAVConfig(); err != nil {
		t.Fatal(err)
	}
	if err := a.clearWebDAVConfig(); err != nil {
		t.Fatal("clear was not idempotent", err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "settings.json"))
	status, statusErr := a.webDAVConfigStatus()
	if err != nil || statusErr != nil || status.Saved || strings.Contains(string(data), webDAVProtectedKey) || !strings.Contains(string(data), "UnknownFuture") {
		t.Fatal("clear did not preserve unrelated settings")
	}
}

func TestWebDAVConfigSaveFailurePreservesExisting(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	initial := appconfig.Settings{Prefs: `{"Other":true}`}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store, settings: initial}
	store.FailSave(errors.New("synthetic failure"))
	if err := a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: "https://example.invalid", Password: "synthetic-secret"}); err == nil {
		t.Fatal("save failure was ignored")
	}
	if a.settings != initial || a.webDAVProtected != "" {
		t.Fatal("failed save mutated active settings")
	}
}
