package app

import (
	"runtime"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/ui"
)

// TraySnapshot is the state the menu bar shows. It has no "测试延迟" item.
type TraySnapshot struct {
	Mode         string
	InlineModes  bool
	Profiles     []TrayProfile
	Groups       []TrayGroup
	ProxyMenu    string
	SystemProxy  bool
	TUN          bool
	TUNAvailable bool
	Lightweight  bool
	Version      string
}

// TrayProfile is one subscription in the tray.
type TrayProfile struct {
	Name    string
	Current bool
}

// TrayGroup is one proxy group in the tray.
type TrayGroup struct {
	Name  string
	Now   string
	Nodes []string
}

// TrayActions are the clicks. Nil functions leave the item in place.
type TrayActions struct {
	Show          func()
	SetMode       func(mode string)
	SelectProfile func(name string)
	SelectNode    func(group, node string)
	SetProxy      func(on bool)
	SetTUN        func(on bool)
	SetLite       func(on bool)
	OpenDir       func(kind string)
	CopyEnv       func()
	CloseAll      func()
	RestartCore   func()
	RestartApp    func()
	Quit          func()
}

// BuildTrayMenu assembles the v2.5.9 tray. The order is the outline in
// docs/spec/outlines/tray.md. There is no delay-test item.
func BuildTrayMenu(s TraySnapshot, act TrayActions) *mygo.Menu {
	if s.Version == "" {
		s.Version = ui.AppVersion
	}
	if s.ProxyMenu == "" {
		s.ProxyMenu = "default"
	}
	mode := s.Mode
	if mode != "global" && mode != "direct" {
		mode = "rule"
	}
	var items []*mygo.MenuItem
	items = append(items, &mygo.MenuItem{
		ID: "dashboard", Label: "仪表板", Accelerator: "CmdOrCtrl+Shift+O",
		Click: func(*mygo.MenuItem, *mygo.Window) {
			if act.Show != nil {
				act.Show()
			}
		},
	})
	items = append(items, mygo.Separator())
	modes := []*mygo.MenuItem{
		modeItem("rule", "规则模式", mode == "rule", act),
		modeItem("global", "全局模式", mode == "global", act),
		modeItem("direct", "直连模式", mode == "direct", act),
	}
	if s.InlineModes {
		items = append(items, modes...)
	} else {
		items = append(items, &mygo.MenuItem{
			ID: "modes", Label: "出站模式 (" + modeWord(mode) + ")", Submenu: modes,
		})
	}
	items = append(items, mygo.Separator())
	items = append(items, &mygo.MenuItem{ID: "profiles", Label: "订阅", Submenu: profileItems(s.Profiles, act)})
	switch s.ProxyMenu {
	case "disable":
	case "inline":
		items = append(items, groupItems(s.Groups, act)...)
	default:
		items = append(items, &mygo.MenuItem{ID: "proxies", Label: "代理", Submenu: groupItems(s.Groups, act)})
	}
	items = append(items,
		mygo.Separator(),
		tunItem(s, act),
		mygo.Separator(),
		checkItem("lite", "轻量模式", s.Lightweight, func(on bool) {
			if act.SetLite != nil {
				act.SetLite(on)
			}
		}),
		&mygo.MenuItem{ID: "dirs", Label: "打开目录", Submenu: []*mygo.MenuItem{
			dirItem("config", "配置目录", act),
			dirItem("core", "内核目录", act),
			dirItem("logs", "日志目录", act),
			dirItem("app-log", "应用日志", act),
			dirItem("core-log", "内核日志", act),
		}},
		&mygo.MenuItem{ID: "more", Label: "更多", Submenu: []*mygo.MenuItem{
			{ID: "copy-env", Label: "复制环境变量", Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.CopyEnv != nil {
					act.CopyEnv()
				}
			}},
			{ID: "close-all", Label: "关闭全部连接", Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.CloseAll != nil {
					act.CloseAll()
				}
			}},
			{ID: "restart-core", Label: "重启内核", Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.RestartCore != nil {
					act.RestartCore()
				}
			}},
			{ID: "restart-app", Label: "重启应用", Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.RestartApp != nil {
					act.RestartApp()
				}
			}},
			{ID: "version", Label: "NetFlow 版本 v" + trimV(s.Version)},
		}},
		mygo.Separator(),
		&mygo.MenuItem{
			ID: "exit", Label: "退出 ⌘Q",
			Accelerator: exitAccel(),
			Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.Quit != nil {
					act.Quit()
				}
			},
		},
	)
	return mygo.NewMenu(items)
}

func modeItem(mode, label string, on bool, act TrayActions) *mygo.MenuItem {
	item := &mygo.MenuItem{ID: "mode-" + mode, Label: label, Type: mygo.MenuItemCheckbox, Checked: on}
	item.Click = func(it *mygo.MenuItem, _ *mygo.Window) {
		it.SetChecked(true)
		if act.SetMode != nil {
			act.SetMode(mode)
		}
	}
	return item
}

func profileItems(list []TrayProfile, act TrayActions) []*mygo.MenuItem {
	if len(list) == 0 {
		return []*mygo.MenuItem{{ID: "profiles-empty", Label: "暂无订阅", Disabled: true}}
	}
	out := make([]*mygo.MenuItem, len(list))
	for i, p := range list {
		name := p.Name
		out[i] = &mygo.MenuItem{ID: "profile-" + name, Label: name, Type: mygo.MenuItemCheckbox, Checked: p.Current, Click: func(*mygo.MenuItem, *mygo.Window) {
			if act.SelectProfile != nil {
				act.SelectProfile(name)
			}
		}}
	}
	return out
}

func groupItems(groups []TrayGroup, act TrayActions) []*mygo.MenuItem {
	if len(groups) == 0 {
		return []*mygo.MenuItem{{ID: "groups-empty", Label: "暂无代理组", Disabled: true}}
	}
	out := make([]*mygo.MenuItem, len(groups))
	for i, g := range groups {
		g := g
		nodes := make([]*mygo.MenuItem, len(g.Nodes))
		for j, name := range g.Nodes {
			name := name
			nodes[j] = &mygo.MenuItem{ID: g.Name + "-" + name, Label: name, Type: mygo.MenuItemCheckbox, Checked: name == g.Now, Click: func(*mygo.MenuItem, *mygo.Window) {
				if act.SelectNode != nil {
					act.SelectNode(g.Name, name)
				}
			}}
		}
		if len(nodes) == 0 {
			nodes = []*mygo.MenuItem{{Label: "暂无节点", Disabled: true}}
		}
		out[i] = &mygo.MenuItem{ID: "group-" + g.Name, Label: g.Name, Submenu: nodes}
	}
	return out
}

func tunItem(s TraySnapshot, act TrayActions) *mygo.MenuItem {
	item := &mygo.MenuItem{ID: "tun", Label: "TUN 模式", Type: mygo.MenuItemCheckbox, Checked: s.TUN, Disabled: !s.TUNAvailable}
	item.Click = func(it *mygo.MenuItem, _ *mygo.Window) {
		if !s.TUNAvailable {
			it.SetChecked(false)
			return
		}
		if act.SetTUN != nil {
			act.SetTUN(it.Checked)
		}
	}
	return item
}

func checkItem(id, label string, on bool, set func(bool)) *mygo.MenuItem {
	item := &mygo.MenuItem{ID: id, Label: label, Type: mygo.MenuItemCheckbox, Checked: on}
	item.Click = func(it *mygo.MenuItem, _ *mygo.Window) {
		if set != nil {
			set(it.Checked)
		}
	}
	return item
}

func dirItem(kind, label string, act TrayActions) *mygo.MenuItem {
	return &mygo.MenuItem{ID: "dir-" + kind, Label: label, Click: func(*mygo.MenuItem, *mygo.Window) {
		if act.OpenDir != nil {
			act.OpenDir(kind)
		}
	}}
}

func modeWord(mode string) string {
	switch mode {
	case "global":
		return "全局"
	case "direct":
		return "直连"
	default:
		return "规则"
	}
}

func trimV(s string) string {
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		return s[1:]
	}
	return s
}

func exitAccel() string {
	if runtime.GOOS == "darwin" {
		return "Cmd+Q"
	}
	return "CmdOrCtrl+Q"
}

func (a *App) traySnapshot() TraySnapshot {
	s := TraySnapshot{Version: ui.AppVersion, ProxyMenu: "default"}
	if a == nil {
		return s
	}
	if a.model == nil {
		s.SystemProxy = a.settings.SystemProxy
		s.TUN = a.settings.TUN
		return s
	}
	s.Mode = a.model.Home.Mode
	s.InlineModes = a.model.Prefs.InlineModes
	s.ProxyMenu = a.model.Prefs.ProxyMenu
	s.SystemProxy = a.settings.SystemProxy
	s.TUN = a.settings.TUN
	s.TUNAvailable = a.model.Home.TUNAvailable
	s.Lightweight = a.model.Prefs.Lightweight
	if a.model.Home.VergeVersion != "" {
		s.Version = a.model.Home.VergeVersion
	}
	for _, p := range a.model.Profiles {
		s.Profiles = append(s.Profiles, TrayProfile{Name: p.Name, Current: p.UID == a.model.CurrentProfile})
	}
	for _, g := range a.model.Groups {
		tg := TrayGroup{Name: g.Name, Now: g.Now}
		for _, n := range g.Nodes {
			tg.Nodes = append(tg.Nodes, n.Name)
		}
		s.Groups = append(s.Groups, tg)
	}
	return s
}

func (a *App) trayActions() TrayActions {
	return TrayActions{
		Show:    a.showMain,
		SetMode: func(mode string) { _ = a.SetMode(mode) },
		SelectNode: func(group, node string) {
			if err := a.SelectProxy(group, node); err != nil && a.model != nil {
				a.model.Notice = err.Error()
			}
		},
		SetProxy: func(on bool) {
			if err := a.SetSystemProxy(on); err != nil && a.model != nil {
				a.model.Notice = err.Error()
			}
		},
		SetTUN: func(on bool) {
			if err := a.SetTUN(on); err != nil && a.model != nil {
				a.model.Notice = err.Error()
			}
		},
		SetLite: func(on bool) {
			if err := a.setLightweight(on); err != nil && a.model != nil {
				a.model.Notice = err.Error()
			}
		},
		OpenDir: a.openDir,
		CopyEnv: func() {
			format := "bash"
			if a.model != nil {
				format = a.model.Prefs.CopyEnv
			}
			if err := writeClipboard(ui.ProxyEnvironment(format, a.proxyEndpoint())); err != nil && a.model != nil {
				a.model.Notice = "复制失败: " + err.Error()
			}
		},
		RestartCore: func() { _ = a.restartCore() },
		Quit:        func() { mygo.App.Quit() },
	}
}

// menuLabels walks a menu, including submenus, for tests.
func menuLabels(items []*mygo.MenuItem) []string {
	var out []string
	for _, it := range items {
		if it == nil {
			continue
		}
		if it.Label != "" {
			out = append(out, it.Label)
		}
		out = append(out, menuLabels(it.Submenu)...)
	}
	return out
}
