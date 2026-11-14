package profile

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptmeta"
)

func TestPatchMetadataIsPartialValidatedAndPreservesExtensions(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	item, err := s.ImportRemote("https://example.invalid/sub?token=synthetic-secret", func(string) ([]byte, error) { return []byte("rules: []"), nil })
	if err != nil {
		t.Fatal(err)
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	f.Items[0].Option.Script = "existing-script"
	if err := s.SaveIfUnchanged(f, snapshot); err != nil {
		t.Fatal(err)
	}
	name, ua, timeout, auto := "updated", "NetFlow-test", 25, true
	updated, err := s.PatchMetadata(item.UID, MetadataPatch{Name: &name, UserAgent: &ua, Timeout: &timeout, AutoUpdate: &auto})
	if err != nil || updated.Name != name || updated.Option.UserAgent != ua || updated.Option.TimeoutSeconds != timeout || !updated.Option.AllowAutoUpdate || updated.Option.Script != "existing-script" || updated.URL != item.URL {
		t.Fatalf("patch lost profile fields: %+v %v", updated, err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	if _, err := s.PatchMetadata(item.UID, MetadataPatch{Name: &name, Timeout: &bad}); err == nil {
		t.Fatal("invalid patch accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("invalid patch changed the catalog")
	}
	local, err := s.ImportLocal("local.yaml", []byte("rules: []"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchMetadata(local.UID, MetadataPatch{AutoUpdate: &auto}); err == nil {
		t.Fatal("local profile accepted remote download option")
	}
}

func TestConfiguredImportCommitsMetadataAndRejectsInvalidBeforeFetch(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	called := false
	metadata := RemoteMetadata{Name: strings.Repeat("a", 257), Option: CatalogOption{UpdateInterval: 60, TimeoutSeconds: 10}}
	fetch := func(string) ([]byte, error) { called = true; return []byte("rules: []"), nil }
	if _, _, err := store.ImportRemoteConfigured("https://example.invalid/sub", fetch, nil, &metadata); err == nil || called {
		t.Fatal("invalid metadata triggered import")
	}
	if _, err := os.Stat(filepath.Join(dir, "profiles")); !os.IsNotExist(err) {
		t.Fatal("invalid import created a profile file")
	}
	metadata = RemoteMetadata{Name: " Name ", Description: " Description ", Option: CatalogOption{UpdateInterval: 60, TimeoutSeconds: 10, UserAgent: "test", AllowAutoUpdate: true}}
	headers := http.Header{"Subscription-Userinfo": []string{"upload=2; download=3; total=100"}}
	item, first, err := store.ImportRemoteConfigured("https://example.invalid/sub", fetch, headers, &metadata)
	if err != nil || !first || item.Name != "Name" || item.Description != "Description" || item.Option.UpdateInterval != 60 || !item.Option.AllowAutoUpdate || item.Used != 5 {
		t.Fatalf("import metadata was not committed: %+v %v", item, err)
	}
	catalog, err := store.Load()
	if err != nil || len(catalog.Items) != 1 || catalog.Items[0].Name != "Name" || catalog.Items[0].Option.UserAgent != "test" {
		t.Fatal("catalog metadata was not persisted")
	}
}

func TestDefaultProfileNameExcludesURLCredentialsAndQuery(t *testing.T) {
	store := NewStore(t.TempDir())
	raw := "https://user:synthetic-password@example.invalid?token=synthetic-token"
	item, err := store.ImportRemote(raw, func(string) ([]byte, error) { return []byte("rules: []"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if item.Name != "example.invalid" || strings.Contains(item.Name, "synthetic-") {
		t.Fatalf("default name exposed URL data: %q", item.Name)
	}
	metadata := RemoteMetadata{Option: CatalogOption{UpdateInterval: 60, TimeoutSeconds: 10}}
	item, _, err = store.ImportRemoteConfigured(raw, func(string) ([]byte, error) { return []byte("rules: []"), nil }, nil, &metadata)
	if err != nil || item.Name != "example.invalid" {
		t.Fatalf("configured import exposed URL data: %q %v", item.Name, err)
	}
}

func TestConditionalCatalogSavePreservesExternalChange(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(File{Current: "initial"}); err != nil {
		t.Fatal(err)
	}
	catalog, snapshot, err := store.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(File{Current: "external"}); err != nil {
		t.Fatal(err)
	}
	catalog.Current = "replacement"
	if err := store.SaveIfUnchanged(catalog, snapshot); !errors.Is(err, safepath.ErrChanged) {
		t.Fatalf("stale catalog accepted: %v", err)
	}
	actual, err := store.Load()
	if err != nil || actual.Current != "external" {
		t.Fatal("external change was overwritten")
	}
}

func TestConditionalCatalogSaveHandlesEmptyExistingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profiles.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(dir)
	catalog, snapshot, err := store.LoadForUpdate()
	if err != nil || snapshot == nil || len(snapshot) != 0 {
		t.Fatal("empty existing catalog confused with a missing file")
	}
	catalog.Current = "entry"
	if err := store.SaveIfUnchanged(catalog, snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteKeepsProfileFileReferencedByAnotherEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join("profiles", "shared.yaml")
	if err := os.WriteFile(filepath.Join(dir, filename), []byte("shared"), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(dir)
	if err := store.Save(File{Current: "active", Items: []CatalogItem{{UID: "active", File: filename}, {UID: "remove", File: filename}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("remove"); err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Load()
	body, readErr := os.ReadFile(filepath.Join(dir, filename))
	if err != nil || len(catalog.Items) != 1 || catalog.Current != "active" || readErr != nil || string(body) != "shared" {
		t.Fatal("deletion removed shared profile data")
	}
}

func TestDeleteKeepsProfileFileReferencedByRollback(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprintf("hardlink-%v", alias), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
				t.Fatal(err)
			}
			original := filepath.Join("profiles", "old.yaml")
			if err := os.WriteFile(filepath.Join(dir, original), []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			retained := original
			if alias {
				retained = filepath.Join("profiles", "alias.yaml")
				if err := os.Link(filepath.Join(dir, original), filepath.Join(dir, retained)); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			}
			store := NewStore(dir)
			catalog := File{Current: "active", Items: []CatalogItem{
				{UID: "active", File: filepath.Join("profiles", "current.yaml"), Option: CatalogOption{VergeScriptPrevious: &scriptmeta.Previous{Subscription: &scriptmeta.SubscriptionSnapshot{File: retained}}}},
				{UID: "remove", File: original},
			}}
			if err := store.Save(catalog); err != nil {
				t.Fatal(err)
			}
			if err := store.Delete("remove"); err != nil {
				t.Fatal(err)
			}
			if body, err := os.ReadFile(filepath.Join(dir, original)); err != nil || string(body) != "retained" {
				t.Fatal("rollback reference was removed", err)
			}
		})
	}
}

func TestDeletePreservesAliasedProfileFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	active, alias := filepath.Join(dir, "profiles", "active.yaml"), filepath.Join(dir, "profiles", "alias.yaml")
	if err := os.WriteFile(active, []byte("shared"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(active, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	store := NewStore(dir)
	if err := store.Save(File{Current: "active", Items: []CatalogItem{{UID: "active", File: filepath.Join("profiles", "active.yaml")}, {UID: "remove", File: filepath.Join("profiles", "alias.yaml")}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("remove"); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(active); err != nil || string(body) != "shared" {
		t.Fatal("active alias was changed")
	}
	if _, err := os.Stat(alias); err != nil {
		t.Fatal("shared file alias was removed")
	}
}

func TestDiscardFirstActiveImportPreservesExistingInactiveProfiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old.yaml", "new.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, "profiles", name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(dir)
	if err := store.Save(File{Current: "new", Items: []CatalogItem{{UID: "old", File: filepath.Join("profiles", "old.yaml")}, {UID: "new", File: filepath.Join("profiles", "new.yaml")}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardFirstImport("new"); err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Load()
	if err != nil || catalog.Current != "" || len(catalog.Items) != 1 || catalog.Items[0].UID != "old" {
		t.Fatal("rollback did not preserve existing inactive profile")
	}
	if _, err := os.Stat(filepath.Join(dir, "profiles", "new.yaml")); !os.IsNotExist(err) {
		t.Fatal("rolled-back profile file remains")
	}
}
