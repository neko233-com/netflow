package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"

	mygoui "github.com/egoist/mygo/ui"
)

// minimalMihomo is a subscription body: one direct node and a selector.
// Nothing in it needs the public network.
const minimalMihomo = `mixed-port: 7897
allow-lan: false
mode: rule
log-level: silent
ipv6: false
proxies:
  - name: n1
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - n1
      - DIRECT
rules:
  - MATCH,DIRECT
`

// TestProfileImportShowsInListAndSurvivesReload drives /profile, imports a
// subscription from a local server, and reads the entry back from a new
// profile store. The kernel is not started. Do not call t.Parallel: mihomo
// is a process-wide singleton.
func TestProfileImportShowsInListAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(minimalMihomo))
	}))
	t.Cleanup(srv.Close)

	raw := srv.URL + "/sub.yaml"
	name := ui.URLHost(raw)

	first := newProfileHarness(dir)
	m := first.Model()
	tt := openProfiles(t, m)
	if listed, _ := profileListed(tt, m, name, raw); listed {
		t.Fatalf("list already shows %q before import", name)
	}
	if err := tt.Click("profile-url"); err != nil {
		t.Fatal(err)
	}
	if !tt.Focused("profile-url") {
		t.Fatal("subscription URL field did not take focus")
	}
	tt.Type(raw)
	if m.ProfileURL != raw {
		t.Fatalf("url field %q, want %q", m.ProfileURL, raw)
	}
	if err := tt.Click("do-import"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/sub.yaml" {
		t.Fatalf("import fetched %q, want /sub.yaml", gotPath)
	}
	if m.ProfileURL != "" {
		t.Fatalf("url field still %q after import, notice %q", m.ProfileURL, m.Notice)
	}
	if ok, why := profileListed(tt, m, name, raw); !ok {
		t.Fatalf("imported %q missing from the list (%s), notice %q, texts %q, profiles %+v", name, why, m.Notice, tt.Texts(), m.Profiles)
	}
	if len(m.Profiles) != 1 || m.Profiles[0].Type != "remote" {
		t.Fatalf("profiles %+v, want one remote entry", m.Profiles)
	}

	// A new store reads the same profiles.json. The harness that wrote it
	// is not involved.
	reloaded, err := profile.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Items) != 1 || reloaded.Items[0].URL != raw || reloaded.Items[0].Name != name || reloaded.Current == "" {
		t.Fatalf("reloaded store %+v", reloaded)
	}
	saved, err := os.ReadFile(filepath.Join(dir, reloaded.Items[0].File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, []byte(minimalMihomo)) {
		t.Fatalf("saved subscription:\n%s", saved)
	}

	restored := newProfileHarness(dir)
	restored.loadProfiles()
	again := restored.Model()
	tt2 := openProfiles(t, again)
	if ok, why := profileListed(tt2, again, name, raw); !ok {
		t.Fatalf("after reload %q is missing (%s), texts %q, profiles %+v", name, why, tt2.Texts(), again.Profiles)
	}
	if len(again.Profiles) != 1 || again.Profiles[0].URL != raw || again.CurrentProfile == "" {
		t.Fatalf("restored %+v current %q", again.Profiles, again.CurrentProfile)
	}
	if again.Home.Profile == nil || again.Home.Profile.Name != name {
		t.Fatalf("home profile %+v", again.Home.Profile)
	}
}

// newProfileHarness wires the window to a profiles.json store without
// Prepare, so the kernel stays stopped.
func newProfileHarness(dir string) *App {
	a := New(Options{
		Dirs:  appdir.Fixed(dir),
		Store: appconfig.NewMemory(dir),
		Proxy: sysproxy.NewMemory(),
		TUN:   tun.NewMemory(),
		Core:  core.New(),
	})
	a.dir = dir
	a.profiles = profile.NewStore(dir)
	a.model = ui.NewModel(ui.HomeState{ConfigDir: dir})
	a.bindHooks()
	return a
}

func openProfiles(t *testing.T, m *ui.Model) *mygoui.Tester {
	t.Helper()
	tt := newPageTester(m)
	if m.Router.Path() != "/profile" {
		if err := tt.Click("订阅"); err != nil {
			t.Fatal(err)
		}
	}
	if m.Router.Path() != "/profile" {
		t.Fatalf("path %q, want /profile", m.Router.Path())
	}
	if _, ok := tt.Find("profile-url"); !ok || !tt.HasText("导入") || !tt.HasText("新建") {
		t.Fatalf("profile import row missing, texts %q", tt.Texts())
	}
	return tt
}

func newPageTester(m *ui.Model) *mygoui.Tester {
	tt := mygoui.NewTester(m.View, ui.WindowWidth, ui.WindowHeight)
	tt.SetScale(1)
	tt.SetDark(false)
	for i := 0; i < 5 && tt.FramePending(); i++ {
		tt.Advance(time.Second)
	}
	return tt
}

func profileListed(tt *mygoui.Tester, m *ui.Model, name, raw string) (bool, string) {
	if m == nil || m.Router.Path() != "/profile" {
		return false, "not on /profile"
	}
	if _, ok := tt.Find("profile-" + name); !ok {
		return false, "no profile card"
	}
	if !tt.HasText(name) {
		return false, "card name is not drawn"
	}
	for _, p := range m.Profiles {
		if p.Name == name && p.Type == "remote" && p.URL == raw {
			return true, ""
		}
	}
	return false, "model has no remote profile for that URL"
}
