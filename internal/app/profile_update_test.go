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
