package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/profile"

	mygoui "github.com/egoist/mygo/ui"
)

// twoNodeSub is a subscription the proxies page can switch. Both nodes are
// direct, so the flow never leaves the machine.
const twoNodeSub = `mixed-port: 7897
allow-lan: false
mode: rule
log-level: silent
ipv6: false
proxies:
  - name: n1
    type: direct
  - name: n2
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - n1
      - n2
rules:
  - MATCH,PROXY
`

// TestImportSelectPersistsAcrossStoreReload is the user path that the
// separate import test and RecordSelected unit test do not cover: import a
// subscription, switch a node on the proxies page, then read the choice
// back from a new profile.Store. The kernel stays stopped. Do not call
// t.Parallel: this package constructs a Core, and mihomo is a process-wide
// singleton.
func TestImportSelectPersistsAcrossStoreReload(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(twoNodeSub))
	}))
	t.Cleanup(srv.Close)

	raw := srv.URL + "/sub.yaml"
	app := newProfileHarness(dir)
	m := app.Model()
	tt := openProfiles(t, m)
	if err := tt.Click("profile-url"); err != nil {
		t.Fatal(err)
	}
	tt.Type(raw)
	if err := tt.Click("do-import"); err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles) != 1 || m.CurrentProfile == "" {
		t.Fatalf("import profiles %+v current %q notice %q", m.Profiles, m.CurrentProfile, m.Notice)
	}
	if len(m.Groups) != 1 || m.Groups[0].Name != "PROXY" {
		t.Fatalf("groups after import %+v notice %q", m.Groups, m.Notice)
	}

	if err := tt.Click("代理"); err != nil {
		t.Fatal(err)
	}
	settlePage(tt)
	if m.Router.Path() != "/proxies" {
		t.Fatalf("path %q", m.Router.Path())
	}
	if m.Groups[0].Now == "n2" {
		t.Fatal("n2 was already selected before the click")
	}
	if err := tt.Click("node-PROXY-n2"); err != nil {
		t.Fatal(err)
	}
	if m.Groups[0].Now != "n2" {
		t.Fatalf("after click now %q notice %q", m.Groups[0].Now, m.Notice)
	}

	reloaded, err := profile.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Items) != 1 || !selectionIs(reloaded.Items[0].Selected, "PROXY", "n2") {
		t.Fatalf("reloaded store lost the choice: %+v", reloaded.Items)
	}

	// Restart: a new window loaded only from that store and config.yaml.
	t.Run("window", func(t *testing.T) {
		again := newProfileHarness(dir)
		again.loadProfiles()
		again.loadGroups()
		page := again.Model()
		view := newPageTester(page)
		if page.Router.Path() != "/proxies" {
			if err := view.Click("代理"); err != nil {
				t.Fatal(err)
			}
			settlePage(view)
		}
		if len(page.Groups) == 0 || page.Groups[0].Now != "n2" || page.Home.Node.Name != "n2" {
			now := ""
			if len(page.Groups) > 0 {
				now = page.Groups[0].Now
			}
			t.Fatalf("restarted window group now %q home %q, want PROXY=n2", now, page.Home.Node.Name)
		}
		if !view.HasText("n2") {
			t.Fatalf("restarted proxies page texts %q", view.Texts())
		}
	})
}

func selectionIs(items []profile.SelectedNode, group, node string) bool {
	for _, it := range items {
		if it.Name == group && it.Now == node {
			return true
		}
	}
	return false
}

func settlePage(tt *mygoui.Tester) {
	for i := 0; i < 5 && tt.FramePending(); i++ {
		tt.Advance(time.Second)
	}
}
