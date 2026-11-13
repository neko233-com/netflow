package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestTestPageLatencyEditAndOrder(t *testing.T) {
	m := DemoModel()
	var probed []string
	var saved [][]SiteTest
	m.Hooks.ProbeSite = func(url string) (int, error) {
		probed = append(probed, url)
		if strings.Contains(url, "apple.com") {
			return 0, errors.New("down")
		}
		return 42, nil
	}
	m.Hooks.SaveSites = func(items []SiteTest) error {
		cp := append([]SiteTest(nil), items...)
		saved = append(saved, cp)
		return nil
	}

	tt := renderModel(m, WindowWidth, 1600, false)
	if !tt.HasText("全部测试") || !tt.HasText("Apple") || !tt.HasText("GitHub") || !tt.HasText("128 ms") {
		t.Fatalf("test page texts %q", tt.Texts())
	}

	if err := tt.Click("site-Apple"); err != nil {
		t.Fatal(err)
	}
	if m.Sites[0].Delay != -1 || m.Sites[0].Status == "testing" || !strings.Contains(m.Notice, "Apple 检测失败") {
		t.Fatalf("apple delay %d status %q notice %q", m.Sites[0].Delay, m.Sites[0].Status, m.Notice)
	}
	if tt.HasText("测试中...") {
		t.Fatal("failed probe stayed on 测试中...")
	}

	if err := tt.Click("site-GitHub"); err != nil {
		t.Fatal(err)
	}
	if m.Sites[1].Delay != 42 || !tt.HasText("42 ms") {
		t.Fatalf("github delay %d texts %q", m.Sites[1].Delay, tt.Texts())
	}

	probed = nil
	if err := tt.Click("test-all"); err != nil {
		t.Fatal(err)
	}
	if len(probed) != len(m.Sites) {
		t.Fatalf("probed %d sites, want %d", len(probed), len(m.Sites))
	}
	if m.Sites[0].Status == "testing" || m.Sites[1].Delay != 42 {
		t.Fatalf("after test all %+v", m.Sites)
	}

	if err := tt.Click("test-new"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("新建测试") {
		t.Fatal("create dialog")
	}
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	if m.Notice != "请输入名称" || !m.TestForm.Open {
		t.Fatalf("empty name notice %q open %v", m.Notice, m.TestForm.Open)
	}
	if err := tt.Click("test-name"); err != nil {
		t.Fatal(err)
	}
	tt.Type("Example")
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	if m.Notice != "请输入测试链接" {
		t.Fatalf("empty url notice %q", m.Notice)
	}
	if err := tt.Click("test-url"); err != nil {
		t.Fatal(err)
	}
	tt.Type("https://example.com")
	if err := tt.Click("test-icon"); err != nil {
		t.Fatal(err)
	}
	tt.Type("E")
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	if m.TestForm.Open || !tt.HasText("Example") || !tt.HasText("https://example.com") {
		t.Fatalf("saved form open %v texts %q", m.TestForm.Open, tt.Texts())
	}
	if len(saved) == 0 || saved[len(saved)-1][len(saved[len(saved)-1])-1].Name != "Example" {
		t.Fatalf("persist %+v", saved)
	}

	if err := tt.RightClick("site-Example"); err != nil {
		t.Fatal(err)
	}
	if err := tt.ChooseMenuItem("编辑"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("编辑测试") {
		t.Fatal("edit dialog")
	}
	m.TestForm.Name = ""
	if err := tt.Click("test-name"); err != nil {
		t.Fatal(err)
	}
	tt.Type("Example 2")
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("Example 2") {
		t.Fatalf("edit texts %q", tt.Texts())
	}

	before := append([]string(nil), siteNames(m)...)
	from, ok := tt.Find("site-Apple")
	if !ok {
		t.Fatal("apple card")
	}
	to, ok := tt.Find("site-YouTube")
	if !ok {
		t.Fatal("youtube card")
	}
	dragSites(tt, from.X+from.W/2, from.Y+from.H/2, to.X+to.W/2, to.Y+to.H/2)
	after := siteNames(m)
	if strings.Join(after, ",") == strings.Join(before, ",") {
		t.Fatalf("order unchanged %v", after)
	}
	if saved[len(saved)-1][0].Name == before[0] && len(saved) == 1 {
		t.Fatal("reorder did not persist")
	}

	if err := tt.RightClick("site-Example 2"); err != nil {
		t.Fatal(err)
	}
	if err := tt.ChooseMenuItem("删除"); err != nil {
		t.Fatal(err)
	}
	if tt.HasText("Example 2") {
		t.Fatal("deleted card still visible")
	}

	m.Hooks.SaveSites = func([]SiteTest) error { return errors.New("disk") }
	if err := tt.Click("test-new"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("test-name"); err != nil {
		t.Fatal(err)
	}
	tt.Type("Nope")
	if err := tt.Click("test-url"); err != nil {
		t.Fatal(err)
	}
	tt.Type("https://nope.example")
	if err := tt.Click("test-save"); err != nil {
		t.Fatal(err)
	}
	if m.Notice != "保存测试项失败" {
		t.Fatalf("save notice %q", m.Notice)
	}
}

func TestTUNToggleNeedsService(t *testing.T) {
	m := DemoModel()
	m.Home.TUNAvailable = false
	m.Home.TUN = false
	m.Router.Replace("/settings")
	calls := 0
	m.Hooks.SetTUN = func(bool) error {
		calls++
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("tun-row"); err != nil {
		t.Fatal(err)
	}
	if m.Home.TUN || calls != 0 || !tt.HasText("TUN 暂不可用：需要特权服务或管理员权限") {
		t.Fatalf("tun %v calls %d notice %q", m.Home.TUN, calls, m.Notice)
	}

	m.Home.TUNAvailable = true
	tt.Frame()
	var got bool
	m.Hooks.SetTUN = func(on bool) error {
		got = on
		return nil
	}
	if err := tt.Click("tun-row"); err != nil {
		t.Fatal(err)
	}
	if !m.Home.TUN || !got {
		t.Fatalf("available toggle tun %v got %v notice %q", m.Home.TUN, got, m.Notice)
	}
	m.Hooks.SetTUN = func(bool) error { return errors.New("denied") }
	if err := tt.Click("tun-row"); err != nil {
		t.Fatal(err)
	}
	if !m.Home.TUN || m.Notice != "denied" {
		t.Fatalf("rollback tun %v notice %q", m.Home.TUN, m.Notice)
	}

	home := DemoModel()
	home.Home.TUNAvailable = false
	home.Home.TUN = false
	home.NetTab = 1
	calls = 0
	home.Hooks.SetTUN = func(bool) error {
		calls++
		return nil
	}
	ht := renderModel(home, WindowWidth, WindowHeight, false)
	if err := ht.Click("switch-虚拟网卡模式"); err != nil {
		t.Fatal(err)
	}
	if home.Home.TUN || calls != 0 || !ht.HasText("TUN 暂不可用：需要特权服务或管理员权限") {
		t.Fatalf("home tun %v calls %d notice %q", home.Home.TUN, calls, home.Notice)
	}
}

func siteNames(m *Model) []string {
	out := make([]string, len(m.Sites))
	for i, s := range m.Sites {
		out[i] = s.Name
	}
	return out
}

func dragSites(tt interface {
	Press(float32, float32)
	Move(float32, float32)
	Release(float32, float32)
}, fromX, fromY, toX, toY float32) {
	tt.Press(fromX, fromY)
	for k := 1; k <= 4; k++ {
		f := float32(k) / 4
		tt.Move(fromX+(toX-fromX)*f, fromY+(toY-fromY)*f)
	}
	tt.Release(toX, toY)
}
