package app

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/sitetest"
	"github.com/neko233-com/netflow/internal/ui"

	mygoui "github.com/egoist/mygo/ui"
)

// TestHomeTestCardProbePersists locks Verge's home TestCard.
// The sidebar 「测试」 route is /unlock. These assertions stay on the home
// page. The kernel is not started. The timeout subtest is
// TestHomeTestCardProbePersists/timeout.
func TestHomeTestCardProbePersists(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	var mode string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		kind := mode
		mu.Unlock()
		switch kind {
		case "hang":
			<-hold
		case "fail":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	a := newProfileHarness(dir)
	m := a.Model()
	client := srv.Client()
	a.model.Hooks.ProbeSite = func(raw string) (int, error) {
		return sitetest.ProbeURL(raw, client)
	}
	tt := mygoui.NewTester(m.View, ui.WindowWidth, 1600)
	tt.SetScale(1)
	for i := 0; i < 5 && tt.FramePending(); i++ {
		tt.Advance(time.Second)
	}
	for _, name := range []string{"Apple", "GitHub", "Google", "YouTube"} {
		if !tt.HasText(name) {
			t.Errorf("default site %s missing, texts %q", name, tt.Texts())
		}
	}
	if !exactText(tt.Texts(), "测试") {
		t.Fatalf("untested tile missing 测试, texts %q", tt.Texts())
	}

	// The tile URL is the local server. Default Apple/GitHub URLs stay
	// unclicked so the test does not dial the public network.
	local := addSite(t, tt, "Local", srv.URL+"/ok")
	if local < 0 {
		t.Fatal("local site was not added")
	}
	if err := tt.Click("site-Local"); err != nil {
		t.Fatal(err)
	}
	if m.Sites[local].Status != "ok" || m.Sites[local].Delay < 0 || !tt.HasText(strconv.Itoa(m.Sites[local].Delay)+" ms") {
		t.Fatalf("probe status %q delay %d texts %q notice %q", m.Sites[local].Status, m.Sites[local].Delay, tt.Texts(), m.Notice)
	}

	mu.Lock()
	mode = "fail"
	mu.Unlock()
	if err := tt.Click("site-Local"); err != nil {
		t.Fatal(err)
	}
	if m.Sites[local].Status != "fail" || m.Notice != "Local 检测失败" || tt.HasText("测试中...") {
		t.Fatalf("fail status %q notice %q texts %q", m.Sites[local].Status, m.Notice, tt.Texts())
	}

	t.Run("timeout", func(t *testing.T) {
		mu.Lock()
		mode = "hang"
		mu.Unlock()
		slow := srv.Client()
		slow.Timeout = 30 * time.Millisecond
		a.model.Hooks.ProbeSite = func(raw string) (int, error) {
			return sitetest.ProbeURL(raw, slow)
		}
		if err := tt.Click("site-Local"); err != nil {
			t.Fatal(err)
		}
		if m.Sites[local].Status == "testing" || tt.HasText("测试中...") {
			t.Fatalf("timeout left the tile testing: %+v", m.Sites[local])
		}
		if m.Notice != "检测超时或失败" || m.Sites[local].Delay == -2 || m.Sites[local].Status == "testing" {
			t.Fatalf("timeout notice %q delay %d status %q", m.Notice, m.Sites[local].Delay, m.Sites[local].Status)
		}
	})

	mu.Lock()
	mode = ""
	mu.Unlock()
	a.model.Hooks.ProbeSite = func(raw string) (int, error) {
		return sitetest.ProbeURL(raw, client)
	}
	if err := tt.RightClick("site-Local"); err != nil {
		t.Fatal(err)
	}
	if err := tt.ChooseMenuItem("编辑"); err != nil {
		t.Fatal(err)
	}
	m.TestForm.Name = ""
	if err := tt.Click("test-name"); err != nil {
		t.Fatal(err)
	}
	tt.Type("Local 2")
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}

	saved, err := sitetest.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 5 || saved[len(saved)-1].Name != "Local 2" || saved[len(saved)-1].URL != srv.URL+"/ok" {
		t.Fatalf("saved tests %+v", saved)
	}
	reloaded := newProfileHarness(dir)
	reloaded.loadSites()
	if len(reloaded.Model().Sites) != 5 || reloaded.Model().Sites[4].Name != "Local 2" || reloaded.Model().Sites[4].Delay != -1 {
		t.Fatalf("reloaded %+v", reloaded.Model().Sites)
	}

	if err := tt.RightClick("site-Local 2"); err != nil {
		t.Fatal(err)
	}
	if err := tt.ChooseMenuItem("删除"); err != nil {
		t.Fatal(err)
	}
	after, err := sitetest.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 4 || containsSite(after, "Local 2") {
		t.Fatalf("after delete %+v", after)
	}
}

func addSite(t *testing.T, tt interface {
	Click(string) error
	Type(string)
}, name, raw string) int {
	t.Helper()
	if err := tt.Click("test-new"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("test-name"); err != nil {
		t.Fatal(err)
	}
	tt.Type(name)
	if err := tt.Click("test-url"); err != nil {
		t.Fatal(err)
	}
	tt.Type(raw)
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	return 4
}

func exactText(texts []string, want string) bool {
	for _, s := range texts {
		if s == want {
			return true
		}
	}
	return false
}

func containsSite(items []sitetest.Item, name string) bool {
	for _, it := range items {
		if it.Name == name {
			return true
		}
	}
	return false
}
