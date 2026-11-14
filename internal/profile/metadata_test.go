package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/scriptmeta"
)

func TestRenameRetainsDisabledScriptHistory(t *testing.T) {
	for _, method := range []string{"patch", "update"} {
		for _, kind := range []string{"local", "remote"} {
			t.Run(fmt.Sprintf("%s-%s", method, kind), func(t *testing.T) {
				store := NewStore(t.TempDir())
				item := CatalogItem{UID: "p", Name: "Old", Type: kind, File: filepath.Join("profiles", "p.yaml"), Option: CatalogOption{VergeScriptPrevious: &scriptmeta.Previous{Approval: &scriptmeta.Approval{}}}}
				if kind == "remote" {
					item.URL = "https://example.invalid/sub?token=private"
				}
				if err := store.Save(File{Items: []CatalogItem{item}}); err != nil {
					t.Fatal(err)
				}
				name := "New"
				if method == "patch" {
					if _, err := store.PatchMetadata("p", MetadataPatch{Name: &name}); err != nil {
						t.Fatal(err)
					}
				} else if err := store.UpdateMetadata("p", name, "", nil); err != nil {
					t.Fatal(err)
				}
				catalog, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				previous := catalog.Items[0].Option.VergeScriptPrevious
				if catalog.Items[0].Name != name || previous == nil || previous.Subscription == nil || previous.Subscription.File != item.File || previous.Subscription.Name != item.Name || previous.Subscription.URL != item.URL {
					t.Fatal("previous script input was not retained")
				}
			})
		}
	}
}

func TestScriptApprovalProtectsProfileNameAcrossMetadataAPIs(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(File{Items: []CatalogItem{{UID: "one", Name: "Old", Type: "remote", Option: CatalogOption{VergeScriptApproval: &scriptmeta.Approval{}}}}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	name, desc := "New", "changed"
	if _, err := store.PatchMetadata("one", MetadataPatch{Name: &name, Description: &desc}); err == nil {
		t.Fatal("patch accepted a name change")
	}
	if err := store.UpdateMetadata("one", name, desc, nil); err == nil {
		t.Fatal("full metadata update accepted a name change")
	}
	after, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("rejected name change modified catalog")
	}
	name = "Old"
	if _, err := store.PatchMetadata("one", MetadataPatch{Name: &name, Description: &desc}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateMetadata("one", "Old", "updated", nil); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMetadataPersistsDownloadOptionsWithoutErasingExtensions(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Save(File{Items: []CatalogItem{{UID: "one", Type: "remote", Option: CatalogOption{Merge: "keep", Rules: "rules"}}}}); err != nil {
		t.Fatal(err)
	}
	opt := CatalogOption{UpdateInterval: 60, AllowAutoUpdate: true, TimeoutSeconds: 30, UserAgent: "Client/1", UseClashProxy: true}
	if err := store.UpdateMetadata("one", "Name", "Description", &opt); err != nil {
		t.Fatal(err)
	}
	file, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got := file.Items[0].Option
	if got.UserAgent != opt.UserAgent || got.TimeoutSeconds != 30 || !got.UseClashProxy || !got.AllowAutoUpdate || got.Merge != "keep" || got.Rules != "rules" {
		t.Fatalf("unexpected options: %+v", got)
	}
	opt.TimeoutSeconds = 301
	if err := store.UpdateMetadata("one", "Bad", "", &opt); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	again, err := store.Load()
	if err != nil || again.Items[0].Name != "Name" {
		t.Fatalf("invalid change was persisted: %+v %v", again, err)
	}
}
