package ui

import (
	"fmt"

	mygoui "github.com/egoist/mygo/ui"
)

func (m *Model) homePage(c *mygoui.Context, pal Palette) {
	m.page(c, pal, "首页", func() {
		if textButton(c, pal, "轻量", "轻量模式", "home-lite") {
			m.setLightweight(true)
		}
		if textButton(c, pal, "手册", "使用手册", "home-manual") {
			c.OpenURL("https://github.com/neko233-com/netflow#readme")
		}
		if textButton(c, pal, "首页设置", "首页设置", "home-settings") {
			m.Draft = m.Cards
			m.HomeEdit = true
		}
	}, func() {
		w, _ := c.Size()
		cols := 1
		if WideLayout(w) {
			cols = 2
		}
		mygoui.Grid(c).Columns(cols).Gap(12).Padding(16).Children(func() {
			if m.Cards.Profile {
				m.profileCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.Proxy {
				m.currentCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.Network {
				m.networkCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.Mode {
				m.modeCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.Traffic {
				m.trafficCard(c, pal).ColumnSpan(cols)
			}
			if m.Cards.Test {
				m.testCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.IP {
				m.ipCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.ClashInfo {
				m.clashCard(c, pal).ColumnSpan(1)
			}
			if m.Cards.SystemInfo {
				m.systemCard(c, pal).ColumnSpan(1)
			}
		})
	})
}

func (m *Model) profileCard(c *mygoui.Context, pal Palette) mygoui.Element {
	title := "订阅"
	if m.Home.Profile != nil && m.Home.Profile.Name != "" {
		title = m.Home.Profile.Name
	}
	return card(c, pal, title, "云", ToneInfo, func() {
		if m.Home.Profile == nil {
			return
		}
		if filledButton(c, pal, "订阅", "home-open-profiles", false) {
			m.goPath("/profile")
		}
	}, func() {
		p := m.Home.Profile
		if p == nil {
			b := mygoui.ButtonBase(c).FillWidth().Padding(16).Radius(8).Label("import-sub")
			b.Children(func() {
				mygoui.Text(c, "导入订阅").FontSize(16).Bold()
				mygoui.Text(c, "点击导入订阅").FontSize(13).TextColor(pal.TextMuted)
			})
			if b.Clicked() {
				m.goPath("/profile")
			}
			return
		}
		if p.Home != "" {
			if textLink(c, pal, "打开主页", p.Home, "profile-home") {
				m.openProfileHome(c, p.Home)
			}
		}
		host := "local"
		if p.URL != "" {
			host = URLHost(p.URL)
		}
		mygoui.Text(c, "来自 "+host).FontSize(13).TextColor(pal.TextMuted)
		if !p.Updated.IsZero() {
			label := "更新时间 " + p.Updated.Format("2006-01-02 15:04")
			if p.Updating || m.ProfileBusy {
				label = "更新中"
			}
			if textLink(c, pal, label, "更新订阅", "profile-update") {
				if m.CurrentProfile != "" && p.URL != "" {
					m.updateProfile(m.CurrentProfile)
				}
			}
		}
		if p.Total > 0 || p.Used > 0 {
			mygoui.Text(c, "已使用 / 总量 "+FormatTraffic(p.Used)+" / "+FormatTraffic(p.Total)).FontSize(13)
			meter(c, pal, UsagePercent(p.Used, p.Total))
		}
		if !p.Expire.IsZero() {
			mygoui.Text(c, "到期时间 "+p.Expire.Format("2006-01-02")).FontSize(13).TextColor(pal.TextMuted)
		}
	})
}

func (m *Model) currentCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "当前节点", "节", ToneSuccess, func() {
		disabled := !DelayTestEnabled(m.Home.Mode, m.Home.Node.Name != "")
		b := mygoui.ButtonBase(c.Key("delay-test")).Height(28).Padding(0, 8).Radius(6).Label("delay-test").Disabled(disabled)
		b.Tooltip("延迟测试")
		b.Children(func() { mygoui.Text(c, "测速").FontSize(13) })
		if b.Clicked() {
			m.testProxyDelay(m.Home.Node.Group, m.Home.Node.Name, "")
		}
		if textButton(c, pal, SortLabel(m.nodeSort()), SortLabel(m.nodeSort()), "node-sort") {
			m.cycleNodeSort()
		}
		if filledButton(c, pal, "代理", "home-open-proxies", false) {
			m.goPath("/proxies")
		}
	}, func() {
		n := m.Home.Node
		if n.Name == "" && (m.Home.Mode == "direct" || n.Group == "") {
			mygoui.Text(c, "暂无激活的代理节点").TextColor(pal.TextMuted)
			return
		}
		mygoui.Row(c).Padding(8).Radius(4).Background(pal.Primary.Alpha(0.05)).Border(1, pal.Primary.Alpha(0.1)).AlignItems(mygoui.Center).Gap(8).Children(func() {
			signalMark(c, pal, n.Delay)
			mygoui.Column(c).Grow(1).Gap(4).Children(func() {
				name := n.Name
				if name == "" {
					name = "暂无激活的代理节点"
				}
				mygoui.Text(c, name).FontSize(14).Bold()
				mygoui.Row(c).Gap(6).Children(func() {
					if n.Type != "" {
						chip(c, pal, n.Type, ToneMuted, false)
					}
					if m.Home.Mode == "global" {
						chip(c, pal, "全局模式", TonePrimary, false)
					}
					if m.Home.Mode == "direct" {
						chip(c, pal, "直连模式", ToneSuccess, false)
					}
					for _, cap := range caps(n.UDP, n.TFO, n.XUDP, n.MPTCP, n.SMUX) {
						chip(c, pal, cap, ToneMuted, false)
					}
				})
			})
			if m.Home.Mode != "direct" && n.Name != "" {
				chip(c, pal, DelayText(n.Delay, DelayTimeout), DelayTone(n.Delay, DelayTimeout), false)
			}
		})
		m.proxySelects(c, pal)
	})
}

func caps(udp, tfo, xudp, mptcp, smux bool) []string {
	var out []string
	if udp {
		out = append(out, "UDP")
	}
	if tfo {
		out = append(out, "TFO")
	}
	if xudp {
		out = append(out, "XUDP")
	}
	if mptcp {
		out = append(out, "MPTCP")
	}
	if smux {
		out = append(out, "SMUX")
	}
	return out
}

func (m *Model) proxySelects(c *mygoui.Context, pal Palette) {
	groups := m.Home.Node.Groups
	if len(groups) == 0 {
		groups = []string{}
		for _, g := range m.Groups {
			groups = append(groups, g.Name)
		}
	}
	group := m.Home.Node.Group
	mygoui.Text(c, "代理组").FontSize(12).TextColor(pal.TextMuted)
	sel := mygoui.Select(c, &group, groups).FillWidth().Disabled(!GroupSelectEnabled(m.Home.Mode)).Label("group-select")
	if sel.Changed() && GroupSelectEnabled(m.Home.Mode) {
		m.selectHomeGroup(group)
	}
	nodes := m.nodesForGroup(m.Home.Node.Group)
	names := make([]string, len(nodes))
	for i, n := range nodes {
		names[i] = n.Name
	}
	node := m.Home.Node.Name
	mygoui.Text(c, "节点").FontSize(12).TextColor(pal.TextMuted)
	ns := mygoui.Select(c, &node, names).FillWidth().Disabled(!NodeSelectEnabled(m.Home.Mode)).Label("node-select")
	if ns.Changed() && NodeSelectEnabled(m.Home.Mode) {
		m.selectHomeNode(node)
	}
}

func (m *Model) selectHomeGroup(name string) {
	for i := range m.Groups {
		g := &m.Groups[i]
		if g.Name != name {
			continue
		}
		m.Home.Node.Group = name
		m.Home.Node.GroupNodes = nil
		m.Home.Node.Name = ""
		m.Home.Node.Type = ""
		m.Home.Node.Delay = -1
		for _, n := range g.Nodes {
			if n.Name == g.Now {
				m.Home.Node.Name = n.Name
				m.Home.Node.Type = n.Type
				m.Home.Node.Delay = n.Delay
				break
			}
		}
		return
	}
}

func (m *Model) selectHomeNode(name string) {
	for i := range m.Groups {
		g := &m.Groups[i]
		if g.Name != m.Home.Node.Group {
			continue
		}
		for _, n := range g.Nodes {
			if n.Name == name {
				if !SelectableGroup(g.Type) {
					m.Notice = "此代理组不支持手动选择"
					return
				}
				m.selectNode(g, n)
				return
			}
		}
	}
}

func (m *Model) nodesForGroup(name string) []ProxyNode {
	if len(m.Home.Node.GroupNodes) > 0 && (name == "" || name == m.Home.Node.Group) {
		return SortNodes(m.Home.Node.GroupNodes, m.nodeSort(), DelayTimeout)
	}
	for _, g := range m.Groups {
		if g.Name == name {
			return SortNodes(g.Nodes, g.Sort, DelayTimeout)
		}
	}
	return nil
}

func (m *Model) nodeSort() int {
	for _, g := range m.Groups {
		if g.Name == m.Home.Node.Group {
			return g.Sort
		}
	}
	return 0
}

func (m *Model) cycleNodeSort() {
	for i := range m.Groups {
		if m.Groups[i].Name == m.Home.Node.Group {
			m.Groups[i].Sort = NextSort(m.Groups[i].Sort)
			return
		}
	}
}

func (m *Model) networkCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "网络设置", "网", TonePrimary, nil, func() {
		mygoui.Row(c).Gap(8).Children(func() {
			if modeFace(c, pal, "系统代理", "tab-system", tabID(m.NetTab), false, m.Home.SystemProxy) {
				m.NetTab = 0
			}
			if modeFace(c, pal, "虚拟网卡模式", "tab-tun", tabID(m.NetTab), false, m.Home.TUN && m.Home.TUNAvailable) {
				m.NetTab = 1
			}
		})
		desc, tip := m.networkDesc()
		mygoui.Row(c).Padding(8).Radius(4).AlignItems(mygoui.Center).Label("net-desc").Children(func() {
			mygoui.Text(c, desc).FontSize(12).TextColor(pal.TextMuted).Grow(1)
			helpMark(c, pal, "help-net", tip)
		})
		on := m.Home.SystemProxy
		label := "系统代理"
		if m.NetTab == 1 {
			on = m.Home.TUN
			label = "虚拟网卡模式"
		}
		mygoui.Row(c).Padding(8).Radius(8).Background(pal.Primary.Alpha(0.04)).AlignItems(mygoui.Center).Children(func() {
			state := "关"
			if on {
				state = "开"
			}
			mygoui.Text(c, state+"  "+label).FontSize(15).FontWeight(500).Grow(1)
			if textButton(c, pal, "设置", label, "net-gear") {
				if m.NetTab == 0 {
					m.Dialogs.Sysproxy = true
				} else {
					m.Dialogs.TUN = true
				}
			}
			sw := mygoui.Switch(c, &on).Label("switch-" + label)
			if sw.Changed() {
				if m.NetTab == 0 {
					m.setProxy(on)
				} else {
					m.setTUN(on)
				}
			}
		})
	})
}

func tabID(tab int) string {
	if tab == 1 {
		return "tab-tun"
	}
	return "tab-system"
}

func (m *Model) networkDesc() (string, string) {
	if m.NetTab == 1 {
		tip := "TUN 模式可以接管所有应用流量，适用于特殊不遵循系统代理设置的应用"
		if !m.Home.TUNAvailable {
			return "TUN 模式需要服务模式，请先安装服务", tip
		}
		if m.Home.TUN {
			return "TUN 模式已启用，应用将通过虚拟网卡访问网络", tip
		}
		return "TUN 模式已关闭，适用于特殊应用", tip
	}
	tip := "修改操作系统的代理设置，如果开启失败，可手动修改操作系统的代理设置"
	if m.Home.SystemProxy {
		return "系统代理已启用，您的应用将通过代理访问网络", tip
	}
	return "系统代理已关闭，建议大多数用户打开此选项", tip
}

func (m *Model) modeCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "代理模式", "模", ToneInfo, nil, func() {
		mygoui.Row(c).Gap(8).Children(func() {
			if modeFace(c, pal, "规则", "mode-rule", "mode-"+m.Home.Mode, true, false) {
				m.setMode("rule")
			}
			if modeFace(c, pal, "全局", "mode-global", "mode-"+m.Home.Mode, true, false) {
				m.setMode("global")
			}
			if modeFace(c, pal, "直连", "mode-direct", "mode-"+m.Home.Mode, true, false) {
				m.setMode("direct")
			}
		})
		mygoui.Text(c, modeDesc(m.Home.Mode)).FontSize(12).TextColor(pal.TextMuted).Padding(8).
			Radius(4).Label("mode-desc")
	})
}

func modeDesc(mode string) string {
	switch mode {
	case "global":
		return "所有流量均通过代理服务器，适用于需要全局科学上网的场景"
	case "direct":
		return "所有流量不经过代理节点，但经过 Clash 内核转发连接目标服务器，适用于需要通过内核进行分流的特定场景"
	case "rule":
		return "基于预设规则智能判断流量走向，提供灵活的代理策略"
	default:
		return "内核通信错误，请重启电脑再试"
	}
}

func (m *Model) trafficCard(c *mygoui.Context, pal Palette) mygoui.Element {
	style := "平滑"
	if !m.ChartSmooth {
		style = "线性"
	}
	return card(c, pal, "流量统计", "速", ToneSecondary, nil, func() {
		if m.Prefs.TrafficGraph {
			box := mygoui.ButtonBase(c.Key("traffic-chart")).FillWidth().Height(130).Radius(8).Label("traffic-chart")
			box.Border(1, pal.Divider).AlignItems(mygoui.Center).Justify(mygoui.Center)
			box.Children(func() {
				mygoui.Text(c, "上传").FontSize(12).TextColor(pal.Secondary)
				mygoui.Text(c, "下载").FontSize(12).TextColor(pal.Primary)
				mygoui.Text(c, style).FontSize(12).TextColor(pal.TextMuted)
			})
			if box.Clicked() {
				m.ChartSmooth = !m.ChartSmooth
			}
		}
		w, _ := c.Size()
		cols := 2
		if WideLayout(w) {
			cols = 3
		}
		type cell struct {
			label, value string
			tone         Tone
		}
		cells := []cell{
			{"上传速度", FormatSpeed(m.Home.UpSpeed), ToneSecondary},
			{"下载速度", FormatSpeed(m.Home.DownSpeed), TonePrimary},
			{"活跃连接", itoa(m.Home.Connections), ToneSuccess},
			{"上传量", FormatTraffic(m.Home.TotalUp), ToneSecondary},
			{"下载量", FormatTraffic(m.Home.TotalDown), TonePrimary},
		}
		if m.Prefs.MemoryUsage {
			cells = append(cells, cell{"Go 堆内存", FormatTraffic(m.Home.Memory), ToneError})
		}
		mygoui.Grid(c).Columns(cols).Gap(8).Children(func() {
			for _, cell := range cells {
				cell := cell
				mygoui.Column(c).Padding(8).Radius(8).Gap(4).Background(pal.Color(cell.tone).Alpha(0.05)).
					Border(1, pal.Color(cell.tone).Alpha(0.15)).Children(func() {
					mygoui.Text(c, cell.label).FontSize(12).TextColor(pal.TextMuted)
					mygoui.Text(c, cell.value).FontSize(16).Bold()
				})
			}
		})
	})
}

func (m *Model) testCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "网站测试", "测", ToneInfo, func() {
		busy := m.sitesBusy()
		label := "全部测试"
		if busy {
			label = "测试中..."
		}
		if textButton(c, pal, label, "测试全部", "test-all") && !busy {
			m.probeAll()
		}
		if textButton(c, pal, "新建", "新建测试", "test-new") {
			m.TestForm = TestForm{Open: true}
		}
	}, func() {
		if len(m.Sites) == 0 {
			emptyState(c, pal)
			return
		}
		mygoui.Grid(c).Columns(4).Gap(8).Children(func() {
			for i := range m.Sites {
				m.testTile(c, pal, i)
			}
		})
	})
}

func (m *Model) ipCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "IP 信息", "IP", ToneInfo, func() {
		label := "查询"
		if m.IPBusy {
			label = "查询中"
		}
		if textButton(c, pal, label, "通过代理查询出口 IP", "ip-refresh") && !m.IPBusy {
			m.refreshIP()
		}
	}, func() {
		if m.IP.Failed != "" {
			mygoui.Text(c, "获取 IP 信息失败："+m.IP.Failed).TextColor(pal.Error)
		}
		if !m.IP.Loaded {
			mygoui.Text(c, "查询会通过代理请求 IP.SB，服务可见代理出口 IP。").FontSize(12).TextColor(pal.TextMuted)
		}
		country := m.IP.Country
		if country == "" {
			country = "未知"
		}
		mygoui.Text(c, country).FontSize(14)
		ip := "••••••••••"
		if m.IPShown {
			ip = m.IP.IP
			if ip == "" {
				ip = "—"
			}
		}
		mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
			mygoui.Text(c, ip).FontSize(12)
			label := "查看"
			if m.IPShown {
				label = "隐藏"
			}
			if textButton(c, pal, label, "切换 IP 显示", "ip-eye") {
				m.IPShown = !m.IPShown
			}
		})
		asn := "N/A"
		if m.IP.ASN != "" {
			asn = m.IP.ASN
		}
		mygoui.Text(c, "自治域 "+asn).FontSize(13).TextColor(pal.TextMuted)
		mygoui.Text(c, "服务商 "+orNA(m.IP.ISP)).FontSize(13)
		mygoui.Text(c, "组织 "+orNA(m.IP.Org)).FontSize(13)
		mygoui.Text(c, "位置 "+orNA(m.IP.Location)).FontSize(13)
		mygoui.Text(c, "时区 "+orNA(m.IP.Timezone)).FontSize(13)
		auto := m.IPAuto
		label := "自动刷新"
		if auto {
			label = fmt.Sprintf("自动刷新: %ds", m.IPLeft)
		}
		mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
			sw := mygoui.Switch(c, &auto).Label("ip-auto")
			mygoui.Text(c, label).FontSize(13)
			if sw.Changed() {
				m.IPAuto = auto
				if auto {
					m.IPLeft = 30
					m.refreshIP()
				}
			}
		})
		code := "N/A"
		if m.IP.Code != "" {
			code = m.IP.Code + ", " + orNA(m.IP.Lon) + ", " + orNA(m.IP.Lat)
		}
		mygoui.Text(c, code).FontSize(12).TextColor(pal.TextMuted)
	})
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func (m *Model) clashCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "Clash 信息", "C", ToneWarning, nil, func() {
		rows := [][2]string{
			{"内核版本", orDash(m.Home.Version)},
			{"系统代理地址", m.proxyAddr()},
			{"混合代理端口", itoa(nonZero(m.Home.MixedPort, 7897))},
			{"运行时间", FormatUptime(m.Home.Uptime)},
			{"规则数量", itoa(m.Home.Rules)},
		}
		for _, row := range rows {
			mygoui.Row(c).FillWidth().Padding(4, 0).Children(func() {
				mygoui.Text(c, row[0]).FontSize(14).TextColor(pal.TextMuted).Grow(1)
				mygoui.Text(c, row[1]).FontSize(14).FontWeight(500)
			})
			mygoui.Box(c).FillWidth().Height(1).Background(pal.Divider)
		}
	})
}

func (m *Model) systemCard(c *mygoui.Context, pal Palette) mygoui.Element {
	return card(c, pal, "系统信息", "系", ToneError, func() {
		if textButton(c, pal, "设置", "设置", "sys-settings") {
			m.goPath("/settings")
		}
	}, func() {
		os := stringsTrim(m.Home.OS + " " + m.Home.OSVersion)
		mygoui.Row(c).FillWidth().Children(func() {
			mygoui.Text(c, "操作系统信息").FontSize(14).TextColor(pal.TextMuted).Grow(1)
			mygoui.Text(c, orDash(os)).FontSize(14)
		})
		launch := "未启用"
		if m.Home.AutoLaunch || m.Prefs.AutoLaunch {
			launch = "已启用"
		}
		if textButton(c, pal, "开机自启 "+launch, "开机自启", "auto-launch") {
			m.setAutoLaunch(!m.Prefs.AutoLaunch)
		}
		mode := RunModeLabel(m.runMode())
		if m.runMode() == RunSidecar {
			b := mygoui.ButtonBase(c.Key("run-mode")).Label("run-mode")
			b.Children(func() {
				mygoui.Text(c, "运行模式 ").FontSize(14).TextColor(pal.TextMuted)
				mygoui.Text(c, mode).FontSize(14).Underline()
			})
			if b.Clicked() {
				m.Notice = "服务模式需要系统服务，当前仍是用户模式"
			}
		} else {
			mygoui.Text(c, "运行模式 "+mode).FontSize(14)
		}
		check := orDash(m.Home.LastCheck)
		if textButton(c, pal, "最后检查更新 "+check, "检查更新", "last-check") {
			m.checkUpdate()
		}
		ver := m.Home.VergeVersion
		if ver == "" {
			ver = AppVersion
		}
		mygoui.Text(c, "NetFlow 版本 v"+trimV(ver)).FontSize(14)
	})
}

func trimV(s string) string {
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		return s[1:]
	}
	return s
}

func orDash(s string) string {
	if s == "" || s == " " {
		return "—"
	}
	return s
}

func nonZero(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[len(s)-1] == ' ') {
		if s[0] == ' ' {
			s = s[1:]
			continue
		}
		s = s[:len(s)-1]
	}
	return s
}
