package ui

import (
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

// Page is one entry in the sidebar. ID is the screenshot file prefix.
// Nav is the sidebar label. Title is the heading on the page.
type Page struct {
	ID    string
	Path  string
	Nav   string
	Title string
	Body  string
}

// Pages is the sidebar, in Clash Verge Rev order.
// The subscription route stays /profile. The proxies heading is 代理组.
func Pages() []Page {
	return []Page{
		{ID: "home", Path: "/home", Nav: "首页", Title: "首页"},
		{ID: "proxies", Path: "/proxies", Nav: "代理", Title: "代理组"},
		{ID: "subscriptions", Path: "/profile", Nav: "订阅", Title: "订阅"},
		{ID: "connections", Path: "/connections", Nav: "连接", Title: "连接", Body: "空空如也"},
		{ID: "rules", Path: "/rules", Nav: "规则", Title: "规则", Body: "空空如也"},
		{ID: "logs", Path: "/logs", Nav: "日志", Title: "日志", Body: "空空如也"},
		{ID: "test", Path: "/unlock", Nav: "测试", Title: "解锁测试", Body: "解锁测试"},
		{ID: "settings", Path: "/settings", Nav: "设置", Title: "设置"},
	}
}

// HomeState is the kernel and network snapshot the home page renders.
// The page does not read the kernel itself.
type HomeState struct {
	Version      string
	Running      bool
	MixedPort    int
	Mode         string
	ConfigDir    string
	Error        string
	SystemProxy  bool
	TUN          bool
	TUNAvailable bool
	Rules        int
	Uptime       time.Duration
	ProxyAddr    string
	UpSpeed      int64
	DownSpeed    int64
	Connections  int
	TotalUp      int64
	TotalDown    int64
	Memory       int64
	Profile      *HomeProfile
	Node         CurrentNode
	OS           string
	OSVersion    string
	AutoLaunch   bool
	RunMode      RunMode
	VergeVersion string
	LastCheck    string
}

// AppVersion is the NetFlow version shown with a leading v.
const AppVersion = "0.2.3-alpha.1"

func pageByPath(path string) (Page, bool) {
	for _, p := range Pages() {
		if p.Path == path {
			return p, true
		}
	}
	return Page{}, false
}

// PlaceholderPage renders a later-milestone page with the Verge title size.
func PlaceholderPage(c *mygoui.Context, title, body string) {
	t := c.Theme()
	mygoui.Column(c).Fill().Children(func() {
		mygoui.Row(c).Height(58).Padding(0, 20).AlignItems(mygoui.Center).Shrink(0).
			BorderWidth(0, 0, 1, 0).BorderColor(t.Border).Children(func() {
			mygoui.Text(c, title).FontSize(PageTitleSize).Bold()
		})
		mygoui.Column(c).Padding(16, 20).Gap(8).Children(func() {
			mygoui.Text(c, body).TextColor(t.TextMuted)
		})
	})
}
