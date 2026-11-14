package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
)

func TestUpdateRemoteProfile(t *testing.T) {
	body := "rules:\n  - MATCH,DIRECT\n"
	var lastAgent atomic.Value
	var info atomic.Value
	info.Store("upload=10; download=20; total=100; expire=1900000000")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAgent.Store(r.Header.Get("User-Agent"))
		w.Header().Set("Subscription-Userinfo", info.Load().(string))
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := newProfileHarness(dir)
	if err := a.ImportURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	f, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	uid, file := f.Current, filepath.Join(dir, f.Items[0].File)
	if f.Items[0].Used != 30 || f.Items[0].Total != 100 || f.Items[0].Expire.Unix() != 1900000000 {
		t.Fatalf("import traffic metadata: %+v", f.Items[0])
	}
	opt := profile.CatalogOption{UpdateInterval: 60, TimeoutSeconds: 10, UserAgent: "NetFlow-test/1"}
	if err := a.profiles.UpdateMetadata(uid, "Test", "", &opt); err != nil {
		t.Fatal(err)
	}
	body = "mode: direct\nrules:\n  - MATCH,DIRECT\n"
	info.Store("upload=40; download=50; total=200; expire=1900000001")
	if err := a.UpdateProfile(uid); err != nil {
		t.Fatal(err)
	}
	if got := lastAgent.Load(); got != opt.UserAgent {
		t.Fatalf("update User-Agent %q", got)
	}
	f, err = a.profiles.Load()
	if err != nil || f.Items[0].Used != 90 || f.Items[0].Total != 200 {
		t.Fatalf("update traffic metadata: %+v %v", f, err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != body {
		t.Fatalf("subscription = %q, %v", got, err)
	}
	config, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body = "broken: ["
	info.Store("upload=999; download=1; total=2000")
	if err := a.UpdateProfile(uid); err == nil {
		t.Fatal("invalid update accepted")
	}
	f, err = a.profiles.Load()
	if err != nil || f.Items[0].Used != 90 || f.Items[0].Total != 200 {
		t.Fatalf("failed update changed metadata: %+v %v", f, err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(after) != string(config) {
		t.Fatalf("failed update changed config: %q %v", after, err)
	}
	after, err = os.ReadFile(file)
	if err != nil || string(after) != string(got) {
		t.Fatalf("failed update changed subscription: %q %v", after, err)
	}
}

func TestProfileUpdatePreservesConcurrentCatalogChangeAndRollsBackFiles(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	initial := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://example.invalid/sub", initial, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	uid, rel, address := catalog.Current, catalog.Items[0].File, catalog.Items[0].URL
	oldProfile, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	engine := &switchTestEngine{running: true, dir: dir}
	engine.onReload = func() {
		if changed {
			return
		}
		changed = true
		f, loadErr := a.profiles.Load()
		if loadErr != nil {
			t.Error(loadErr)
			return
		}
		f.Items[0].Description = "external change"
		if saveErr := a.profiles.Save(f); saveErr != nil {
			t.Error(saveErr)
		}
	}
	a.core = engine
	err = a.updateProfileData(uid, address, []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil)
	if !errors.Is(err, safepath.ErrChanged) {
		t.Fatalf("expected external catalog conflict, got %v", err)
	}
	actual, loadErr := a.profiles.Load()
	profileBody, readErr := os.ReadFile(filepath.Join(dir, rel))
	configBody, configErr := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if loadErr != nil || actual.Items[0].Description != "external change" || readErr != nil || string(profileBody) != string(oldProfile) || configErr != nil || string(configBody) != string(oldConfig) {
		t.Fatal("concurrent catalog or old configuration was not preserved")
	}
}

func TestUpdateSharedProfileUsesIndependentFile(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active-%v", active), func(t *testing.T) {
			dir := t.TempDir()
			a := newProfileHarness(dir)
			old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
			if err := a.importURLData("https://first.invalid/sub", old, nil); err != nil {
				t.Fatal(err)
			}
			if err := a.importURLData("https://second.invalid/sub", old, nil); err != nil {
				t.Fatal(err)
			}
			catalog, snapshot, err := a.profiles.LoadForUpdate()
			if err != nil {
				t.Fatal(err)
			}
			catalog.Items[1].File = catalog.Items[0].File
			if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
				t.Fatal(err)
			}
			target, other := 1, 0
			if active {
				target, other = 0, 1
			}
			oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			next := []byte("mode: direct\nrules: ['MATCH,DIRECT']\n")
			if err := a.updateProfileData(catalog.Items[target].UID, catalog.Items[target].URL, next, nil); err != nil {
				t.Fatal(err)
			}
			updated, err := a.profiles.Load()
			if err != nil {
				t.Fatal(err)
			}
			if updated.Items[target].File == updated.Items[other].File {
				t.Fatal("shared path was not separated")
			}
			gotTarget, err := os.ReadFile(filepath.Join(dir, updated.Items[target].File))
			if err != nil || string(gotTarget) != string(next) {
				t.Fatal("updated profile missing")
			}
			gotOther, err := os.ReadFile(filepath.Join(dir, updated.Items[other].File))
			if err != nil || string(gotOther) != string(old) {
				t.Fatal("other profile was changed")
			}
			gotConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil || (!active && string(gotConfig) != string(oldConfig)) || (active && !strings.Contains(string(gotConfig), "mode: direct")) {
				t.Fatal("active configuration was not updated correctly")
			}
		})
	}
}

func TestSharedProfileUpdateRollsBackOnCatalogConflict(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://first.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.importURLData("https://second.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	catalog.Items[1].File = catalog.Items[0].File
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(filepath.Join(dir, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &switchTestEngine{running: true, dir: dir}
	changed := false
	engine.onReload = func() {
		if changed {
			return
		}
		changed = true
		current, e := a.profiles.Load()
		if e != nil {
			t.Error(e)
			return
		}
		current.Items[1].Description = "external change"
		if e := a.profiles.Save(current); e != nil {
			t.Error(e)
		}
	}
	a.core = engine
	if err := a.updateProfileData(catalog.Items[0].UID, catalog.Items[0].URL, []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil); !errors.Is(err, safepath.ErrChanged) {
		t.Fatalf("catalog conflict ignored: %v", err)
	}
	after, err := os.ReadDir(filepath.Join(dir, "profiles"))
	if err != nil || len(before) != len(after) {
		t.Fatal("failed update left the copied profile behind")
	}
	current, err := a.profiles.Load()
	if err != nil || current.Items[1].Description != "external change" || current.Items[0].File != current.Items[1].File {
		t.Fatal("catalog rollback lost external edit")
	}
}

func TestProfileUpdateRejectsTUNTransitionBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://example.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	a.tunBusy = true
	if err := a.updateProfileData(catalog.Items[0].UID, catalog.Items[0].URL, []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil); err == nil {
		t.Fatal("update accepted during TUN transition")
	}
	data, err := os.ReadFile(filepath.Join(dir, catalog.Items[0].File))
	if err != nil || string(data) != string(old) {
		t.Fatal("profile changed during TUN transition")
	}
}

func TestSharedProfileUpdatePreservesConcurrentSourceEdit(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://first.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.importURLData("https://second.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	catalog.Items[1].File = catalog.Items[0].File
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(filepath.Join(dir, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	external := []byte("mode: global\nrules: ['MATCH,DIRECT']\n")
	engine := &switchTestEngine{running: true, dir: dir}
	changed := false
	engine.onReload = func() {
		if !changed {
			changed = true
			if e := os.WriteFile(filepath.Join(dir, catalog.Items[0].File), external, 0600); e != nil {
				t.Error(e)
			}
		}
	}
	a.core = engine
	if err := a.updateProfileData(catalog.Items[0].UID, catalog.Items[0].URL, []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil); err == nil {
		t.Fatal("external source edit was ignored")
	}
	got, err := os.ReadFile(filepath.Join(dir, catalog.Items[0].File))
	if err != nil || string(got) != string(external) {
		t.Fatal("external source edit was lost")
	}
	after, err := os.ReadDir(filepath.Join(dir, "profiles"))
	if err != nil || len(before) != len(after) {
		t.Fatal("failed update left copied file")
	}
}

func TestProfileURLReplacementPreservesLegacyNameRedaction(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	oldURL := "https://user:synthetic-password@first.invalid?token=synthetic-token"
	body := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData(oldURL, body, nil); err != nil {
		t.Fatal(err)
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	catalog.Items[0].Name = "user:synthetic-password@first.invalid?token=synthetic-token"
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := a.updateProfileDataWithURL(catalog.Items[0].UID, oldURL, "https://second.invalid/new", body, nil); err != nil {
		t.Fatal(err)
	}
	list, err := a.agentProfiles()
	encoded, _ := json.Marshal(list)
	if err != nil || strings.Contains(string(encoded), "synthetic-") || list.Profiles[0].Name != "first.invalid" {
		t.Fatalf("legacy name became exposed: %s %v", encoded, err)
	}
}

func TestProfileURLReplacementRestoresFilesAfterReloadFailure(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://old.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a.core = &failingDNSReloadEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir}}
	if err := a.updateProfileDataWithURL(catalog.Items[0].UID, catalog.Items[0].URL, "https://new.invalid/sub", []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"), nil); err == nil {
		t.Fatal("reload failure was ignored")
	}
	current, err := a.profiles.Load()
	if err != nil || current.Items[0].URL != catalog.Items[0].URL {
		t.Fatal("failed replacement changed the URL")
	}
	file, fileErr := os.ReadFile(filepath.Join(dir, catalog.Items[0].File))
	config, configErr := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if fileErr != nil || configErr != nil || string(file) != string(old) || string(config) != string(oldConfig) {
		t.Fatal("failed replacement did not restore files")
	}
}

func TestProfileURLReplacementRejectsSourceEditedDuringDownload(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	old := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://old.invalid/sub", old, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	source, err := a.snapshotProfileSource(catalog.Items[0].File)
	if err != nil {
		t.Fatal(err)
	}
	external := []byte("mode: global\nrules: ['MATCH,DIRECT']\n")
	path := filepath.Join(dir, catalog.Items[0].File)
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.updateProfileDataWithSource(catalog.Items[0].UID, catalog.Items[0].URL, "https://new.invalid/sub", old, nil, &source); err == nil {
		t.Fatal("replacement ignored external edit")
	}
	current, err := a.profiles.Load()
	file, fileErr := os.ReadFile(path)
	if err != nil || fileErr != nil || current.Items[0].URL != catalog.Items[0].URL || string(file) != string(external) {
		t.Fatal("external edit or old URL was lost")
	}
}
