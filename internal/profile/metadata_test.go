package profile

import "testing"

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
