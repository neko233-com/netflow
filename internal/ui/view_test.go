package ui

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode"

	mygoui "github.com/egoist/mygo/ui"
)

// Window-free page locks live in sidebar_logo_test.go, proxies_select_test.go,
// and text_lock_test.go. Importing a subscription and reloading the profile
// store is internal/app/profile_import_test.go.

func demoHome() HomeState {
	return HomeState{
		Version:     "1.19.33",
		Running:     true,
		MixedPort:   7897,
		Mode:        "rule",
		ConfigDir:   "~/Library/Application Support/app.clashgo.desktop",
		SystemProxy: false,
		TUN:         false,
	}
}

func TestHomeShowsKernelStatus(t *testing.T) {
	m := NewModel(demoHome())
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	for _, text := range []string{"首页", "内核版本", "1.19.33", "混合代理端口", "7897", "运行时间", "0:00:00", "规则数量", "当前节点", "虚拟网卡", "代理模式", "流量统计", "网站测试", "Apple", "IP 信息", "Clash 信息", "系统信息"} {
		if !tt.HasText(text) {
			t.Errorf("home missing %q", text)
		}
	}
	if !tt.HasText("运行中") || !tt.HasText("NetFlow") {
		t.Fatal("sidebar title")
	}
}

func TestBrandAssetMatchesSpec(t *testing.T) {
	spec, err := os.ReadFile("../app/assets/tray.png")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spec, netflowBrandPNG) {
		t.Fatal("sidebar and tray artwork differ")
	}
}

func TestSidebarBrandMark(t *testing.T) {
	m := NewModel(demoHome())
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("netflow-mark") || !tt.HasText("NetFlow") {
		t.Fatal("brand mark is not next to the app name")
	}
	mark, ok := tt.Find("netflow-mark")
	name, nameOK := tt.Find("NetFlow")
	if !ok || !nameOK {
		t.Fatal("missing brand mark or name")
	}
	if mark.W < 34 || mark.W > 38 || mark.H < 34 || mark.H > 38 {
		t.Fatalf("icon size %v, want 36", mark)
	}
	// 20px row padding plus the spec's margin-left of -3.
	if mark.X < 15 || mark.X > 19 {
		t.Fatalf("logo inset %v, want about 17", mark)
	}
	gap := name.X - (mark.X + mark.W)
	if gap < 3 || gap > 8 {
		t.Fatalf("wordmark gap %v (mark %v name %v)", gap, mark, name)
	}
	if mark.Y < 0 || mark.Y+mark.H > logoRowHeight+1 {
		t.Fatalf("icon outside the 58px logo row: %v", mark)
	}
	assertCyanMark(t, tt.Image(), mark)

	ct := NewCollapsedTester(m, false)
	requireCollapsedBrand(t, ct)
	requireCollapsedBrand(t, NewCollapsedTester(nil, false))
	collapsed, ok := ct.Find("netflow-mark")
	if !ok {
		t.Fatal("collapsed sidebar lost the mark")
	}
	assertCyanMark(t, ct.Image(), collapsed)
}

func requireCollapsedBrand(t *testing.T, tt *mygoui.Tester) {
	t.Helper()
	got, ok := MeasureCollapsedBrand(tt)
	if !ok {
		t.Fatal("collapsed frame is missing the sidebar, the 56px logo slot, or the mark")
	}
	if got.Wordmark {
		t.Fatal("collapsed sidebar still shows NetFlow")
	}
	if got.SidebarW < 70 || got.SidebarW > 74 {
		t.Fatalf("sidebar width %v, want 72", got.SidebarW)
	}
	if got.SlotW < 54 || got.SlotW > 58 || got.SlotH < 54 || got.SlotH > 58 {
		t.Fatalf("logo slot %v×%v, want 56×56", got.SlotW, got.SlotH)
	}
	if got.MarkW < 34 || got.MarkW > 38 || got.MarkH < 34 || got.MarkH > 38 {
		t.Fatalf("mark %v×%v, want 36×36", got.MarkW, got.MarkH)
	}
}

func assertCyanMark(t *testing.T, img image.Image, mark mygoui.Rect) {
	t.Helper()
	blue := 0
	for y := int(mark.Y); y < int(mark.Y+mark.H); y++ {
		for x := int(mark.X); x < int(mark.X+mark.W); x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			if b > r*13/10 && b > g*11/10 {
				blue++
			}
		}
	}
	if blue < 20 {
		t.Fatalf("brand mark has too few visible blue pixels: %d", blue)
	}
}

func TestNavigatePages(t *testing.T) {
	m := NewModel(demoHome())
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	for _, p := range Pages() {
		if p.ID == "home" {
			continue
		}
		if err := tt.Click(p.Nav); err != nil {
			t.Fatal(err)
		}
		if m.Router.Path() != p.Path {
			t.Fatalf("path %q after clicking %s, want %s", m.Router.Path(), p.Nav, p.Path)
		}
		if !tt.HasText(p.Title) {
			t.Fatalf("page %s missing title %q", p.ID, p.Title)
		}
		if p.Body != "" && !tt.HasText(p.Body) {
			t.Fatalf("page %s missing %q", p.ID, p.Body)
		}
	}
	if err := tt.Click("首页"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("1.19.33") {
		t.Fatal("home version disappeared")
	}
}

// TestM1ShellLocks freezes the three M1 shell fixes from issue #5.
// ui.NewTester does not expose a text node's font size, so the 20px
// token is the exported PageTitleSize used by the headings.
func TestM1ShellLocks(t *testing.T) {
	t.Run("subscriptions path", func(t *testing.T) {
		var subs Page
		var found bool
		for _, p := range Pages() {
			if p.Path == "/subscriptions" {
				t.Fatal("subscriptions nav must use /profile, not /subscriptions")
			}
			if p.ID == "subscriptions" || p.Nav == "订阅" {
				subs = p
				found = true
			}
		}
		if !found || subs.Path != "/profile" || subs.Nav != "订阅" {
			t.Fatalf("subscriptions page %+v, want path /profile and nav 订阅", subs)
		}
		m := NewModel(demoHome())
		tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
		if err := tt.Click("订阅"); err != nil {
			t.Fatal(err)
		}
		if m.Router.Path() != "/profile" {
			t.Fatalf("path %q after clicking 订阅, want /profile", m.Router.Path())
		}
		if !hasExactText(tt, "订阅") {
			t.Fatalf("texts %q", tt.Texts())
		}
	})

	t.Run("proxies title", func(t *testing.T) {
		var title string
		for _, p := range Pages() {
			if p.ID == "proxies" {
				title = p.Title
			}
		}
		if title != "代理组" {
			t.Fatalf("proxies title %q, want 代理组", title)
		}
		m := NewModel(demoHome())
		tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
		if err := tt.Click("代理"); err != nil {
			t.Fatal(err)
		}
		if m.Router.Path() != "/proxies" {
			t.Fatalf("path %q", m.Router.Path())
		}
		if !hasExactText(tt, "代理组") {
			t.Fatalf("texts %q, want an exact 代理组 title", tt.Texts())
		}
	})

	t.Run("page title size", func(t *testing.T) {
		if PageTitleSize != 20 {
			t.Fatalf("PageTitleSize %v, want 20", PageTitleSize)
		}
		m := NewModel(demoHome())
		tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
		if !hasExactText(tt, "首页") {
			t.Fatalf("home title missing, texts %q", tt.Texts())
		}
		if err := tt.Click("代理"); err != nil {
			t.Fatal(err)
		}
		if !hasExactText(tt, "代理组") {
			t.Fatalf("proxies title missing, texts %q", tt.Texts())
		}
	})
}

func hasExactText(tt *mygoui.Tester, s string) bool {
	for _, text := range tt.Texts() {
		if text == s {
			return true
		}
	}
	return false
}

func TestStoppedHome(t *testing.T) {
	m := NewModel(HomeState{Version: "1.19.33", Error: "内核没有启动"})
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("已停止") || !tt.HasText("内核没有启动") || !tt.HasText("内核未运行") {
		t.Fatalf("texts %q", tt.Texts())
	}
}

func TestHomeSettingsCancelDoesNotHide(t *testing.T) {
	m := NewModel(demoHome())
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("home-settings"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("订阅卡") || !tt.HasText("系统信息卡") {
		t.Fatal("settings dialog")
	}
	if err := tt.Click("订阅卡"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("home-cancel"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("导入订阅") {
		t.Fatal("cancel hid the profile card")
	}
	if err := tt.Click("home-settings"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("订阅卡"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("home-save"); err != nil {
		t.Fatal(err)
	}
	if tt.HasText("导入订阅") {
		t.Fatal("save kept the profile card")
	}
	if !m.Cards.Proxy || m.Cards.Profile {
		t.Fatalf("cards %+v", m.Cards)
	}
}

func TestDirectModeDisablesNodeControls(t *testing.T) {
	m := NewModel(demoHome())
	m.Home.Node = CurrentNode{Group: "Proxy", Name: "香港 01", Type: "ss", Delay: 128}
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("mode-direct"); err != nil {
		t.Fatal(err)
	}
	if m.Home.Mode != "direct" || !tt.HasText("直连模式") {
		t.Fatalf("mode %s", m.Home.Mode)
	}
	if err := tt.Click("delay-test"); err != nil {
		t.Fatal(err)
	}
	if m.Home.Node.Delay == DelayTesting {
		t.Fatal("delay test ran in direct mode")
	}
}

func TestHomeColumnsFollowWidth(t *testing.T) {
	wide := NewModel(demoHome())
	wt := mygoui.NewTester(wide.View, WindowWidth, WindowHeight)
	narrowModel := NewModel(demoHome())
	nt := mygoui.NewTester(narrowModel.View, 520, 520)
	wr, ok := wt.Find("当前节点")
	if !ok {
		t.Fatal("wide title")
	}
	ir, ok := wt.Find("导入订阅")
	if !ok {
		t.Fatal("wide import")
	}
	if wr.X <= ir.X {
		t.Fatalf("wide layout stacked: node x=%v import x=%v", wr.X, ir.X)
	}
	nr, ok := nt.Find("当前节点")
	if !ok {
		t.Fatal("narrow title")
	}
	ni, ok := nt.Find("导入订阅")
	if !ok {
		t.Fatal("narrow import")
	}
	if nr.Y <= ni.Y+20 {
		t.Fatalf("narrow layout is still two columns: node y=%v import y=%v", nr.Y, ni.Y)
	}
}

func TestIPMaskAndChart(t *testing.T) {
	m := DemoModel()
	tt := renderModel(m, WindowWidth, 1400, false)
	if !tt.HasText("••••••••••") {
		t.Fatal("ip not masked")
	}
	if tt.HasText("203.0.113.10") {
		t.Fatal("ip visible while masked")
	}
	if err := tt.Click("ip-eye"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("203.0.113.10") {
		t.Fatal("ip stayed masked")
	}
	if !tt.HasText("自动刷新") || tt.HasText("自动刷新:") {
		t.Fatal("countdown while auto refresh is off")
	}
	if err := tt.Click("traffic-chart"); err != nil {
		t.Fatal(err)
	}
	if m.ChartSmooth || !tt.HasText("线性") {
		t.Fatal("chart did not switch to linear")
	}
}

func TestProxyEmptyAndChain(t *testing.T) {
	m := NewModel(demoHome())
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("代理"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("代理组") || !tt.HasText("尚未导入订阅") || !tt.HasText("前往订阅") {
		t.Fatal("no-subscription empty state")
	}
	m.Home.Mode = "direct"
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	m.Router.Replace("/proxies")
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("直连模式") {
		t.Fatal("direct page")
	}
	if tt.HasText("尚未导入订阅") {
		t.Fatal("direct page showed the subscription empty state")
	}

	m = DemoModel()
	m.Router.Replace("/proxies")
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("香港 01") || !tt.HasText("Selector") {
		t.Fatal("groups")
	}
	if err := tt.Click("chain-toggle"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("我明白，开启") || !tt.HasText("保持关闭") {
		t.Fatal("chain confirm")
	}
	if err := tt.Click("chain-keep"); err != nil {
		t.Fatal(err)
	}
	if m.Chain.On {
		t.Fatal("keep disabled turned the chain on")
	}
	if err := tt.Click("chain-toggle"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("chain-enable"); err != nil {
		t.Fatal(err)
	}
	if !m.Chain.On || !tt.HasText("链式代理模式") {
		t.Fatal("chain did not enable")
	}
}

func TestProfileImportAndDelete(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/profile")
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("订阅") || !tt.HasText("粘贴") || !tt.HasText("新建") {
		t.Fatal("import row")
	}
	m.ProfileURL = "ftp://example.com/a"
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("do-import"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("无效的订阅链接") {
		t.Fatalf("notice %q", m.Notice)
	}
	m.Notice = ""
	m.ProfileURL = "https://example.com/sub"
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("清除") {
		t.Fatal("clear should replace paste")
	}
	if err := tt.Click("do-import"); err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles) != 1 || m.Profiles[0].Name != "example.com" {
		t.Fatalf("profiles %+v", m.Profiles)
	}

	m.Form = ProfileForm{Open: true, Type: "remote", Interval: 60, Auto: true, URL: "https://example.com/b", Name: "短间隔"}
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("1440") || !tt.HasText("使用系统代理更新") {
		t.Fatal("remote form")
	}
	if err := tt.Click("form-save"); err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles) != 2 {
		t.Fatalf("saved %d", len(m.Profiles))
	}

	m.DeleteUID = m.Profiles[0].UID
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("此操作不可逆") {
		t.Fatal("delete confirm")
	}
	if err := tt.Click("delete-ok"); err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles) != 1 {
		t.Fatalf("after delete %+v", m.Profiles)
	}
}

func TestProfileMenuRemoteHasExtraItems(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/profile")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.RightClick("示例订阅"); err != nil {
		t.Fatal(err)
	}
	menu := tt.Menu()
	joined := join(menu)
	for _, item := range []string{"首 页", "分享二维码", "更新", "更新（代理）", "删除"} {
		if !containsText(joined, item) {
			t.Fatalf("remote menu missing %s in %v", item, menu)
		}
	}
	if err := tt.RightClick("本地配置"); err != nil {
		t.Fatal(err)
	}
	local := join(tt.Menu())
	if containsText(local, "分享二维码") || containsText(local, "更新（代理）") {
		t.Fatalf("local menu %v", tt.Menu())
	}
}

func TestSettingsSections(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	for _, title := range []string{"系统设置", "Clash 设置", "Verge 基础设置", "Verge 高级设置", "简体中文", "浅色", "深色", "系统", "v" + AppVersion} {
		if !tt.HasText(title) {
			t.Errorf("settings missing %q", title)
		}
	}
	if runtime.GOOS == "linux" && !m.ForceTray {
		t.Fatal("demo should force the tray row so the macOS screenshot shows it")
	}
	if !tt.HasText("托盘点击事件") {
		t.Fatal("tray click row")
	}
	port, pok := tt.Find("7897")
	chev, cok := tt.Find(settingsChevron)
	if !pok || !cok || port.X+port.W > chev.X {
		t.Fatalf("chevron should sit to the right of the port value, port %v chevron %v", port, chev)
	}
	plain := NewModel(demoHome())
	plain.Router.Replace("/settings")
	pt := mygoui.NewTester(plain.View, WindowWidth, WindowHeight)
	if runtime.GOOS == "linux" && pt.HasText("托盘点击事件") {
		t.Fatal("linux build showed 托盘点击事件")
	}
	if runtime.GOOS != "linux" && !pt.HasText("托盘点击事件") {
		t.Fatal("macOS build hid 托盘点击事件")
	}

	m.Prefs.SocksOn = true
	m.Prefs.SocksPort = m.Prefs.MixedPort
	m.Dialogs.Ports = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("已启用的监听端口不能重复") {
		t.Fatal("duplicate port")
	}
	if runtime.GOOS == "linux" && !tt.HasText("Tproxy") {
		t.Fatal("linux port dialog")
	}
	if runtime.GOOS != "linux" && tt.HasText("Tproxy") {
		t.Fatal("non-linux tproxy row")
	}

	m.Dialogs.Ports = false
	m.DNSAsk = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("仍然开启") || !tt.HasText("保持关闭") {
		t.Fatal("dns confirm buttons")
	}
	m.Dialogs.Misc = true
	m.DNSAsk = false
	m.Prefs.ProxyColumns = AutoProxyColumns
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("自动") || !tt.HasText("内部值 6") {
		t.Fatal("auto columns")
	}
	m.Dialogs.Misc = false
	m.Dialogs.Theme = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("主要颜色") || !tt.HasText("成功颜色") {
		t.Fatal("theme swatches")
	}
	m.Dialogs.Theme = false
	m.Dialogs.Hotkey = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("打开面板") || !tt.HasText("重新激活订阅") {
		t.Fatal("hotkeys")
	}
	m.Dialogs.Hotkey = false
	m.Dialogs.Backup = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("启用定时备份") || !tt.HasText("24") {
		t.Fatal("backup defaults")
	}
}

func TestManualOpensDocs(t *testing.T) {
	m := NewModel(demoHome())
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("home-manual"); err != nil {
		t.Fatal(err)
	}
	if len(tt.OpenedURLs()) != 1 || tt.OpenedURLs()[0] != "https://github.com/neko233-com/netflow#readme" {
		t.Fatalf("urls %v", tt.OpenedURLs())
	}
}

func TestPaperColors(t *testing.T) {
	m := NewModel(demoHome())
	light := renderModel(m, WindowWidth, WindowHeight, false).Image()
	darkModel := NewModel(demoHome())
	darkModel.Prefs.ThemeMode = "dark"
	dark := renderModel(darkModel, WindowWidth, WindowHeight, false).Image()
	lr, lg, lb, _ := light.At(4, 4).RGBA()
	if lr>>8 != 0xF5 || lg>>8 != 0xF5 || lb>>8 != 0xF5 {
		t.Fatalf("light paper #%02x%02x%02x", lr>>8, lg>>8, lb>>8)
	}
	dr, dg, db, _ := dark.At(4, 4).RGBA()
	if dr>>8 != 0x2E || dg>>8 != 0x30 || db>>8 != 0x3D {
		t.Fatalf("dark paper #%02x%02x%02x", dr>>8, dg>>8, db>>8)
	}
}

func TestPageScreenshots(t *testing.T) {
	dir := os.Getenv("CLASHGO_SCREENSHOT_DIR")
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, theme := range []struct {
		name string
		dark bool
	}{{"light", false}, {"dark", true}} {
		for _, p := range Pages() {
			m := DemoModel()
			if theme.dark {
				m.Prefs.ThemeMode = "dark"
			} else {
				m.Prefs.ThemeMode = "light"
			}
			if p.Path != "/home" {
				m.Router.Replace(p.Path)
			}
			tt := renderModel(m, WindowWidth, WindowHeight, theme.dark)
			img := tt.Image()
			b := img.Bounds()
			if b.Dx() != WindowWidth || b.Dy() != WindowHeight {
				t.Fatalf("%s-%s is %dx%d", p.ID, theme.name, b.Dx(), b.Dy())
			}
			if dir == "" {
				continue
			}
			path := filepath.Join(dir, p.ID+"-"+theme.name+".png")
			if err := writePNG(path, img); err != nil {
				t.Fatal(err)
			}
			if p.ID == "connections" {
				list := DemoModel()
				list.Conns.Layout = "list"
				if theme.dark {
					list.Prefs.ThemeMode = "dark"
				} else {
					list.Prefs.ThemeMode = "light"
				}
				list.Router.Replace("/connections")
				lt := renderModel(list, WindowWidth, WindowHeight, theme.dark)
				if err := writePNG(filepath.Join(dir, "connections-list-"+theme.name+".png"), lt.Image()); err != nil {
					t.Fatal(err)
				}
			}
		}
		ct := NewCollapsedTester(DemoModel(), theme.dark)
		requireCollapsedBrand(t, ct)
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, "sidebar-collapsed-"+theme.name+".png")
		if err := writePNG(path, ct.Image()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProxySelectWritesSelector(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/proxies")
	var gotGroup, gotNode string
	var calls int
	m.Hooks.SelectProxy = func(group, node string) error {
		calls++
		gotGroup, gotNode = group, node
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !hasExactText(tt, "代理组") {
		t.Fatal("proxies title")
	}
	if err := tt.Click("node-Proxy-香港 02"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || gotGroup != "Proxy" || gotNode != "香港 02" {
		t.Fatalf("selector write %d %s %s", calls, gotGroup, gotNode)
	}
	if m.Groups[0].Now != "香港 02" {
		t.Fatalf("selected now %q", m.Groups[0].Now)
	}
	if m.Home.Node.Name != "香港 02" || m.Home.Node.Group != "Proxy" {
		t.Fatalf("home node %+v", m.Home.Node)
	}
	// URLTest groups also support the kernel's explicit selection operation.
	if err := tt.Click("node-Auto-台湾 01"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || gotGroup != "Auto" || gotNode != "台湾 01" {
		t.Fatalf("urltest selection missing, calls %d %s %s", calls, gotGroup, gotNode)
	}
	if m.Groups[1].Now != "台湾 01" {
		t.Fatalf("urltest now %q", m.Groups[1].Now)
	}

	m.Hooks.SelectProxy = func(string, string) error { return errSelect }
	if err := tt.Click("node-Proxy-香港 01"); err != nil {
		t.Fatal(err)
	}
	if m.Groups[0].Now != "香港 02" || m.Notice != errSelect.Error() {
		t.Fatalf("failed select now %q notice %q", m.Groups[0].Now, m.Notice)
	}
}

var errSelect = errString("selector rejected")

type errString string

func (e errString) Error() string { return string(e) }

func TestTwoCharacterButtonsHaveNoSpacer(t *testing.T) {
	want := []string{"订阅", "代理", "首页", "连接", "规则", "日志", "测试", "设置", "导入", "新建", "更新", "手册"}
	for _, path := range []string{"/home", "/proxies", "/profile", "/settings"} {
		m := DemoModel()
		if path != "/home" {
			m.Router.Replace(path)
		}
		tt := renderModel(m, WindowWidth, WindowHeight, false)
		for _, s := range tt.Texts() {
			if spacedHanPair(s) {
				t.Errorf("%s shows %q", path, s)
			}
		}
		if path == "/home" {
			for _, label := range want[:2] {
				if !hasExactText(tt, label) {
					t.Errorf("home missing exact %q", label)
				}
			}
		}
	}
	m := NewModel(demoHome())
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	for _, label := range want {
		spaced := []rune(label)
		if len(spaced) == 2 {
			bad := string([]rune{spaced[0], ' ', spaced[1]})
			if tt.HasText(bad) {
				t.Errorf("home contains %q", bad)
			}
		}
	}
}

func spacedHanPair(s string) bool {
	r := []rune(s)
	if len(r) != 3 || r[1] != ' ' {
		return false
	}
	return unicode.Is(unicode.Han, r[0]) && unicode.Is(unicode.Han, r[2])
}

func TestProfileDividerStaysWithCards(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/profile")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	d, ok := tt.Find("profile-rule")
	if !ok {
		t.Fatal("missing profile divider")
	}
	if d.X < sidebarExpandedWidth+4 || d.X+d.W > float32(WindowWidth)-8 {
		t.Fatalf("divider %v extends outside the card column", d)
	}
}

func TestSettingsRowChevronFormat(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, 1600, false)
	rows := []string{
		"ports", "external", "webui", "core-row", "geo", "tunnels",
		"theme-row", "layout-row", "misc-row", "hotkey-row", "backup",
		"runtime-row", "conf-dir", "core-dir", "log-dir", "check-update",
		"devtools", "lite-row", "quit-row",
	}
	if runtime.GOOS == "windows" {
		rows = append(rows, "uwp")
	}
	texts := tt.Texts()
	n := 0
	for _, s := range texts {
		if !strings.Contains(s, "›") {
			continue
		}
		n++
		if s != settingsChevron {
			t.Errorf("settings row renders %q, want value + one space + › (%q)", s, settingsChevron)
		}
	}
	if n != len(rows) {
		t.Fatalf("chevron count %d, want one per settings row (%d)", n, len(rows))
	}
	for _, id := range rows {
		if _, ok := tt.Find(id); !ok {
			t.Errorf("missing settings row %s", id)
		}
	}
	sawPort := false
	for i, s := range texts {
		if s != "7897" {
			continue
		}
		sawPort = true
		if i+1 >= len(texts) || texts[i+1] != settingsChevron {
			t.Fatalf("port row near %q, want %q", texts[max(0, i-1):min(len(texts), i+3)], "7897"+settingsChevron)
		}
	}
	if !sawPort {
		t.Fatal("port value missing")
	}
}

func TestProfileCardLinesAlignLeft(t *testing.T) {
	m := DemoModel()
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	home, okH := tt.Find("打开主页")
	from, okF := tt.Find("来自 example.com")
	updated, okU := tt.Find("更新时间 2026-11-02 09:30")
	if !okH || !okF || !okU {
		t.Fatalf("profile lines home %v from %v updated %v texts %q", okH, okF, okU, tt.Texts())
	}
	if home.X > from.X+4 || updated.X > from.X+4 {
		t.Fatalf("profile body is not left aligned: home %v from %v updated %v", home, from, updated)
	}
}

func TestDescriptionBarsHaveNoPrimaryBorder(t *testing.T) {
	m := DemoModel()
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	img := tt.Image()
	for _, id := range []string{"net-desc", "mode-desc"} {
		r, ok := tt.Find(id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		x := int(r.X + 2)
		y := int(r.Y)
		if x < 0 || y < 0 || x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
			t.Fatalf("%s at %v is outside the frame", id, r)
		}
		rr, gg, bb, _ := img.At(x, y).RGBA()
		if rr>>8 < 0x30 && gg>>8 > 0x50 && bb>>8 > 0xD0 {
			t.Fatalf("%s still has a primary border #%02x%02x%02x", id, rr>>8, gg>>8, bb>>8)
		}
	}
}

func TestSettingsHelpMarksUseQuestion(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, 1600, false)
	if hasExactText(tt, "?") || hasExactText(tt, "i") {
		t.Fatal("help marks are icons, not ? or i text")
	}
	marks := []struct{ id, row string }{
		{"help-silent", "静默启动"},
		{"help-dns", "DNS 覆写"},
		{"help-unified", "统一延迟"},
		{"help-backup", "备份设置"},
		{"help-conf", "配置目录"},
		{"help-lite", "轻量模式设置"},
	}
	for _, mark := range marks {
		icon, ok := tt.Find(mark.id)
		row, okRow := tt.Find(mark.row)
		if !ok || !okRow || icon.X <= row.X || !overlapsY(icon.Y, icon.H, row.Y, row.H) {
			t.Fatalf("help %s icon %v row %s %v", mark.id, icon, mark.row, row)
		}
	}
}

func TestThemeModeIsJoined(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	light, okL := tt.Find("theme-light")
	dark, okD := tt.Find("theme-dark")
	system, okS := tt.Find("theme-system")
	if !okL || !okD || !okS {
		t.Fatal("theme segments")
	}
	if gap := dark.X - (light.X + light.W); gap > 1 {
		t.Fatalf("theme buttons are separate, gap %v", gap)
	}
	if gap := system.X - (dark.X + dark.W); gap > 1 {
		t.Fatalf("theme buttons are separate, gap %v", gap)
	}
	if light.Y != dark.Y || dark.Y != system.Y {
		t.Fatalf("theme buttons are not one row: %v %v %v", light, dark, system)
	}
}

func TestImportDisabledIsGray(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/profile")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	assertImportFill(t, tt, false)
	if err := tt.Click("do-import"); err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles) != 0 {
		t.Fatal("disabled import added a profile")
	}
	m.ProfileURL = "https://example.com/a"
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	assertImportFill(t, tt, true)
}

func assertImportFill(t *testing.T, tt *mygoui.Tester, enabled bool) {
	t.Helper()
	r, ok := tt.Find("do-import")
	if !ok {
		t.Fatal("import button")
	}
	x, y := int(r.X+r.W/2), int(r.Y+r.H/2)
	img := tt.Image()
	if x < 0 || y < 0 || x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
		t.Fatalf("import button %v outside the frame", r)
	}
	rr, gg, bb, _ := img.At(x, y).RGBA()
	primary := rr>>8 < 0x30 && gg>>8 > 0x50 && bb>>8 > 0xD0
	if enabled && !primary {
		t.Fatalf("enabled import #%02x%02x%02x, want primary", rr>>8, gg>>8, bb>>8)
	}
	if !enabled && primary {
		t.Fatalf("disabled import is still light blue #%02x%02x%02x", rr>>8, gg>>8, bb>>8)
	}
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

func join(parts []string) string { return strings.Join(parts, "\n") }

func containsText(s, sub string) bool { return strings.Contains(s, sub) }
