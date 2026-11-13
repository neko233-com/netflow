package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
)

func TestUpdateRemoteProfile(t *testing.T) {
	body := "rules:\n  - MATCH,DIRECT\n"
	var lastAgent atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAgent.Store(r.Header.Get("User-Agent"))
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
	opt := profile.CatalogOption{UpdateInterval: 60, TimeoutSeconds: 10, UserAgent: "NetFlow-test/1"}
	if err := a.profiles.UpdateMetadata(uid, "Test", "", &opt); err != nil {
		t.Fatal(err)
	}
	body = "mode: direct\nrules:\n  - MATCH,DIRECT\n"
	if err := a.UpdateProfile(uid); err != nil {
		t.Fatal(err)
	}
	if got := lastAgent.Load(); got != opt.UserAgent {
		t.Fatalf("update User-Agent %q", got)
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
	if err := a.UpdateProfile(uid); err == nil {
		t.Fatal("invalid update accepted")
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
