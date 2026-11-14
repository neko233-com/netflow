package ui

import (
	"strings"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

func (m *Model) proxyPage(c *mygoui.Context, pal Palette) {
	title := "代理组"
	if m.Chain.On {
		title = "链式代理模式"
	}
	m.fixedPage(c, pal, title, func() {
		if m.Chain.On {
			mygoui.Text(c, "!").TextColor(pal.Warning).Tooltip("链式代理会显著降低网速。如果您没有明确的业务需求，或不了解此项配置，请保持关闭")
		}
		if textButton(c, pal, "代理集合", "代理集合", "providers") {
			m.Dialogs.Provider = true
		}
		if filledButton(c, pal, "规则", "proxy-mode-rule", m.Home.Mode == "rule") {
			m.setMode("rule")
		}
		if filledButton(c, pal, "全局", "proxy-mode-global", m.Home.Mode == "global") {
			m.setMode("global")
		}
		if filledButton(c, pal, "直连", "proxy-mode-direct", m.Home.Mode == "direct") {
			m.setMode("direct")
		}
		if filledButton(c, pal, "链式代理", "chain-toggle", m.Chain.On) {
			if m.Hooks.ChainAvailable != nil && !m.Hooks.ChainAvailable() {
				m.Notice = "链式代理尚未接入内核"
				return
			}
			if m.Chain.Connecting {
				m.Notice = "代理链正在连接"
				return
			}
			if m.Chain.On {
				if m.Chain.Connected {
					if m.Hooks.DisconnectChain == nil {
						m.Notice = "代理链服务不可用"
						return
					}
					if err := m.Hooks.DisconnectChain(); err != nil {
						m.Notice = err.Error()
						return
					}
				}
				m.Chain = ChainState{}
			} else {
				m.Chain.Ask = true
			}
		}
	}, func() {
		if !m.Prefs.GroupIcon && m.groupIcons != nil {
			m.groupIcons.cancelPending()
		}
		reason := m.proxyReason()
		if reason != EmptyNone {
			m.resetProxyNavigation()
		}
		if reason == EmptyDirect {
			m.directEmpty(c, pal)
			return
		}
		if reason == EmptyLoading {
			mygoui.Text(c, "加载中...").Padding(24).TextColor(pal.TextMuted)
			return
		}
		if reason != EmptyNone {
			m.proxyEmpty(c, pal, reason)
			return
		}
		mygoui.Row(c).Grow(1).FillWidth().AlignItems(mygoui.Stretch).Children(func() {
			mygoui.Scroll(c).Grow(1).FillHeight().Children(func() {
				mygoui.Column(c).FillWidth().Children(func() {
					if m.Chain.On {
						m.chainPanel(c, pal)
					}
					mygoui.Column(c).FillWidth().Padding(8).Gap(8).Children(func() {
						for i := range m.Groups {
							if !m.Groups[i].Hidden {
								m.groupBlock(c, pal, i)
							}
						}
					})
				})
			})
			if m.Home.Mode == "rule" || m.Home.Mode == "global" {
				mygoui.Scroll(c).Width(36).FillHeight().Children(func() { m.letterNav(c, pal) })
			}
		})
	})
}

func (m *Model) proxyReason() EmptyReason {
	count := 0
	for _, g := range m.Groups {
		if !g.Hidden {
			count++
		}
	}
	return ResolveProxyList(ProxyListInput{
		Mode:            m.Home.Mode,
		Loading:         m.ProxiesLoading,
		SubscriptionCnt: m.subscriptionCount(),
		HasCurrent:      m.currentProfile() != nil,
		CoreRunning:     m.Home.Running,
		CoreError:       m.Home.Error != "",
		GroupCount:      count,
	})
}

func (m *Model) directEmpty(c *mygoui.Context, pal Palette) {
	mygoui.Column(c).FillWidth().Padding(48).AlignItems(mygoui.Center).Gap(12).Children(func() {
		mygoui.Column(c).Size(64, 48).Radius(8).Border(2, pal.TextMuted)
		mygoui.Text(c, "直连模式").FontSize(16).TextColor(pal.TextMuted)
	})
}

func (m *Model) proxyEmpty(c *mygoui.Context, pal Palette, reason EmptyReason) {
	title, desc := "", ""
	switch reason {
	case EmptyNoSubs:
		title, desc = "尚未导入订阅", "代理页没有可展示的内容。请先前往“订阅”页面导入并启用订阅。"
	case EmptyInactive:
		title, desc = "尚未激活订阅", "检测到已有订阅，但当前没有有效订阅被激活。请前往“订阅”页面选择并激活一个订阅。"
	case EmptyCore:
		title, desc = "内核暂不可用", "无法从内核获取代理信息。请尝试重启内核；若问题仍然存在，请打开日志目录检查内核日志。"
	default:
		title, desc = "未获取到代理信息", "当前没有可展示的代理组或节点。请检查当前订阅是否包含有效的代理组和节点，或尝试重启内核并查看日志。"
	}
	mygoui.Column(c).FillWidth().Padding(24).AlignItems(mygoui.Center).Gap(8).Children(func() {
		box := mygoui.Column(c).MaxWidth(640).Padding(16).Gap(8).Radius(8).Border(1, pal.Warning)
		box.Children(func() {
			mygoui.Text(c, title).FontSize(16).Bold()
			mygoui.Text(c, desc).FontSize(13).TextColor(pal.TextMuted)
			mygoui.Row(c).Gap(8).Children(func() {
				if reason == EmptyNoSubs || reason == EmptyInactive || reason == EmptyNoInfo {
					if filledButton(c, pal, "前往订阅", "empty-profiles-"+string(reason), true) {
						m.goPath("/profile")
					}
				}
				if reason == EmptyCore || reason == EmptyNoInfo {
					if filledButton(c, pal, "重启内核", "empty-restart-"+string(reason), true) {
						if m.Hooks.RestartCore != nil {
							if err := m.Hooks.RestartCore(); err != nil {
								m.Notice = err.Error()
							}
						}
					}
					if filledButton(c, pal, "打开日志目录", "empty-logs-"+string(reason), false) {
						if m.Hooks.OpenDir != nil {
							m.Hooks.OpenDir("logs")
						}
					}
				}
			})
		})
	})
}

func (m *Model) chainPanel(c *mygoui.Context, pal Palette) {
	mygoui.Column(c).Padding(12).Gap(8).Margin(8).Radius(8).Background(pal.Card).Children(func() {
		mygoui.Text(c, "代理链配置").FontSize(16).Bold()
		if len(m.Chain.Nodes) == 0 {
			mygoui.Text(c, "链式代理会显著降低网速。如果您没有明确的业务需求，或不了解此项配置，请保持关闭").FontSize(13).TextColor(pal.TextMuted)
			if filledButton(c, pal, "关闭", "chain-close", false) {
				m.Chain = ChainState{}
			}
			return
		}
		if m.Chain.Warning != "" {
			mygoui.Text(c, m.Chain.Warning).FontSize(13).TextColor(pal.Warning)
		}
		if m.Chain.Target != "" {
			mygoui.Text(c, "目标组: "+m.Chain.Target).FontSize(13).TextColor(pal.TextMuted)
		}
		for i, n := range m.Chain.Nodes {
			tag := n.Name
			if i == 0 {
				tag += " 入口"
			}
			if i == len(m.Chain.Nodes)-1 && len(m.Chain.Nodes) > 1 {
				tag += " 出口"
			}
			mygoui.Text(c, tag).FontSize(14)
		}
		if len(m.Chain.Nodes) == 1 {
			mygoui.Text(c, "链式代理至少需要 2 个节点，请再添加一个节点。").FontSize(13).TextColor(pal.Warning)
		} else {
			mygoui.Text(c, "顺序点击节点添加到代理链中").FontSize(13).TextColor(pal.TextMuted)
		}
		ok, tip := ChainConnectEnabled(len(m.Chain.Nodes), m.Chain.Connecting, m.Chain.Connected)
		label := "连接"
		if m.Chain.Connected {
			label = "断开"
		}
		if m.Chain.Connecting {
			label = "连接中..."
		}
		b := mygoui.ButtonBase(c.Key("chain-connect")).Height(32).MinWidth(90).Radius(6).Disabled(!ok && !m.Chain.Connected).Label("chain-connect")
		if tip != "" {
			b.Tooltip(tip)
		}
		if m.Chain.Connected {
			b.Background(pal.Error).TextColor(pal.OnPrimary)
		} else {
			b.Background(pal.Success).TextColor(pal.OnPrimary)
		}
		b.Children(func() { mygoui.Text(c, label).FontSize(13) })
		if b.Clicked() {
			if m.Chain.Connected {
				if m.Hooks.DisconnectChain == nil {
					m.Notice = "代理链服务不可用"
					return
				}
				if err := m.Hooks.DisconnectChain(); err != nil {
					m.Notice = err.Error()
					return
				}
				m.Chain.Connected = false
			} else if ok {
				if m.Hooks.ConnectChainAsync == nil {
					m.Notice = "代理链服务不可用"
					return
				}
				m.Chain.Connecting = true
				m.Hooks.ConnectChainAsync(m.Chain.Target, append([]ProxyNode(nil), m.Chain.Nodes...), func(err error) {
					m.Chain.Connecting = false
					if err != nil {
						m.Notice = err.Error()
						return
					}
					m.Chain.Connected = true
					m.Notice = "代理链已连接，新连接将使用目标组的代理链"
				})
			}
		}
		if !m.Chain.Connected && !m.Chain.Connecting && textButton(c, pal, "删除链式配置", "删除链式配置", "chain-clear") {
			m.Chain.Nodes = nil
			m.Chain.Target = ""
		}
	})
}

func (m *Model) resetProxyNavigation() {
	m.proxyJumpTarget = ""
	m.proxyHoverLetter = ""
	m.proxyHoverAt = time.Time{}
	m.proxyHoverFired = false
}

func (m *Model) letterNav(c *mygoui.Context, pal Palette) {
	seen := map[string]bool{}
	hovered := false
	mygoui.Column(c).Width(28).Padding(8, 0).Gap(2).AlignItems(mygoui.Center).Children(func() {
		for i := range m.Groups {
			g := &m.Groups[i]
			if g.Hidden {
				continue
			}
			letter := GroupLetter(g.Name)
			if letter == "" || seen[letter] {
				continue
			}
			seen[letter] = true
			b := mygoui.ButtonBase(c.Key("letter-"+letter)).Height(28).Padding(0, 8).Radius(6).Label("letter-" + letter)
			b.Background(mygoui.Transparent).TextColor(pal.Text).Tooltip(letter)
			b.Children(func() { mygoui.Text(c, letter).FontSize(13) })
			jump := b.Clicked()
			if m.Prefs.HoverNav && b.Hovered() {
				hovered = true
				if m.proxyHoverLetter != letter {
					m.proxyHoverLetter = letter
					m.proxyHoverAt = c.Now()
					m.proxyHoverFired = false
				}
				delay := time.Duration(m.Prefs.HoverDelay) * time.Millisecond
				if delay < 0 {
					delay = 0
				}
				if delay > 5*time.Second {
					delay = 5 * time.Second
				}
				remaining := delay - c.Now().Sub(m.proxyHoverAt)
				if !m.proxyHoverFired && remaining <= 0 {
					jump = true
					m.proxyHoverFired = true
				} else if !m.proxyHoverFired {
					c.After(remaining)
				}
			}
			if jump {
				g.Open = true
				m.proxyJumpTarget = g.Name
				c.Invalidate()
				if b.Hovered() {
					m.proxyHoverFired = true
				}
			}
		}
	})
	if !hovered {
		m.proxyHoverLetter = ""
		m.proxyHoverAt = time.Time{}
		m.proxyHoverFired = false
	}
}

func (m *Model) groupBlock(c *mygoui.Context, pal Palette, i int) {
	g := &m.Groups[i]
	mygoui.Column(c).FillWidth().Radius(8).Background(pal.Card).Children(func() {
		head := mygoui.ButtonBase(c.Key("group-"+g.Name)).FillWidth().Padding(4, 8).Radius(8).Label("group-" + g.Name)
		if m.proxyJumpTarget == g.Name {
			head.ScrollIntoView()
			m.proxyJumpTarget = ""
		}
		head.Children(func() {
			mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Gap(8).Children(func() {
				mygoui.Column(c).Grow(1).Children(func() {
					mygoui.Row(c).Gap(6).AlignItems(mygoui.Center).Children(func() {
						if m.Prefs.GroupIcon && g.Icon != "" {
							if m.groupIcons == nil {
								m.groupIcons = newGroupIconCache()
							}
							services := c.Services()
							if icon := m.groupIcons.get(g.Icon, m.Hooks.LoadGroupIcon, services.Invalidate); icon != nil {
								mygoui.Image(c, icon).Size(20, 20).Label("group-icon-" + g.Name)
							}
						}
						mygoui.Text(c, g.Name).FontSize(14).Bold()
						chip(c, pal, g.Type, ToneMuted, false)
					})
					if g.Now != "" {
						mygoui.Text(c, g.Now).FontSize(12).TextColor(pal.TextMuted)
					}
				})
				chip(c, pal, itoa(len(g.Nodes)), TonePrimary, false)
				m.groupTools(c, pal, g)
				arrow := "▸"
				if g.Open {
					arrow = "▾"
				}
				mygoui.Text(c, arrow).FontSize(12).TextColor(pal.TextMuted)
			})
		})
		if head.Clicked() {
			g.Open = !g.Open
		}
		if !g.Open {
			return
		}
		if g.FilterOpen || g.URLOpen {
			m.groupEditor(c, pal, g)
		}
		w, _ := c.Size()
		cols := ProxyColumns(contentWidth(w, m.sidebarWidth()), m.Prefs.ProxyColumns)
		nodes := SortNodes(FilterNodes(g.Nodes, g.FilterApplied, SearchOpts{}, DelayTimeout), g.Sort, DelayTimeout)
		if len(nodes) == 0 {
			mygoui.Column(c).Padding(12).AlignItems(mygoui.Center).Children(func() {
				mygoui.Text(c, "暂无代理").TextColor(pal.TextMuted)
			})
			return
		}
		if cols <= 1 {
			mygoui.Column(c).Padding(8).Gap(8).Children(func() {
				for _, n := range nodes {
					m.nodeRow(c, pal, g, n, false)
				}
			})
			return
		}
		mygoui.Grid(c).Columns(cols).Gap(8).Padding(8).Children(func() {
			for _, n := range nodes {
				m.nodeRow(c, pal, g, n, true)
			}
		})
	})
}

func (m *Model) groupTools(c *mygoui.Context, pal Palette, g *ProxyGroup) {
	mygoui.Row(c).Gap(2).Children(func() {
		if textButton(c, pal, "定位", "当前节点", "locate-"+g.Name) {
			g.Open = true
		}
		if textButton(c, pal, "测速", "延迟测试", "delay-"+g.Name) {
			g.Open = true
			names := make([]string, 0, len(g.Nodes))
			for _, node := range g.Nodes {
				if !node.Preset {
					names = append(names, node.Name)
				}
			}
			for _, name := range names {
				m.testProxyDelay(g.Name, name, g.TestURL)
			}
		}
		if textButton(c, pal, sortMark(g.Sort), SortLabel(g.Sort), "sort-"+g.Name) {
			g.Open = true
			g.Sort = NextSort(g.Sort)
		}
		urlMark := "链"
		if g.URLOpen {
			urlMark = "链开"
		}
		if textButton(c, pal, urlMark, "延迟测试链接", "url-"+g.Name) {
			g.Open = true
			g.URLOpen = !g.URLOpen
			g.FilterOpen = false
		}
		detail := "细节"
		tip := "展示节点细节"
		if g.ShowDetail {
			detail = "简"
			tip = "隐藏节点细节"
		}
		if textButton(c, pal, detail, tip, "detail-"+g.Name) {
			g.ShowDetail = !g.ShowDetail
		}
		filter := "过滤"
		if g.FilterOpen {
			filter = "收起"
		}
		if textButton(c, pal, filter, "过滤节点", "filter-"+g.Name) {
			if !g.FilterOpen {
				g.Open = true
			}
			g.FilterOpen = !g.FilterOpen
			g.URLOpen = false
			if !g.FilterOpen {
				g.FilterApplied = strings.TrimSpace(g.FilterText)
				g.FilterChanged = time.Time{}
			}
		}
	})
}

func sortMark(mode int) string {
	switch mode {
	case 1:
		return "延迟"
	case 2:
		return "名称"
	default:
		return "默认"
	}
}

func (m *Model) groupEditor(c *mygoui.Context, pal Palette, g *ProxyGroup) {
	if g.FilterOpen {
		field := mygoui.TextInput(c, &g.FilterText).Placeholder("过滤条件").FillWidth().Label("filter-" + g.Name)
		field.Background(pal.Card)
		if field.Changed() {
			g.FilterChanged = c.Now()
		}
	}
	if g.URLOpen {
		mygoui.TextInput(c, &g.TestURL).Placeholder("延迟测试链接").FillWidth()
	}
}

func (m *Model) nodeRow(c *mygoui.Context, pal Palette, g *ProxyGroup, n ProxyNode, mini bool) {
	h := float32(40)
	if mini {
		h = 56
	}
	selected := g.Now == n.Name
	row := mygoui.ButtonBase(c.Key("node-"+g.Name+"-"+n.Name)).FillWidth().Height(h).Radius(4).Padding(0, 8).Label("node-" + g.Name + "-" + n.Name)
	if selected {
		row.Background(pal.SelectedFill()).BorderWidth(0, 0, 0, 3).BorderColor(pal.NodeBar())
	} else {
		row.Background(pal.Node)
	}
	row.AlignItems(mygoui.Center)
	row.Children(func() {
		mygoui.Column(c).Grow(1).Children(func() {
			label := n.Name
			if g.ShowDetail && n.Now != "" {
				label += " - " + n.Now
			}
			mygoui.Text(c, label).FontSize(14).SingleLine()
			mygoui.Row(c).Gap(4).Children(func() {
				if n.Type != "" {
					chip(c, pal, n.Type, ToneMuted, false)
				}
				if g.ShowDetail {
					for _, cap := range caps(n.UDP, n.TFO, n.XUDP, n.MPTCP, n.SMUX) {
						chip(c, pal, cap, ToneMuted, false)
					}
				}
			})
		})
		if n.Preset {
			return
		}
		if n.Delay == DelayTesting {
			mygoui.Text(c, "testing").FontSize(12).TextColor(pal.TextMuted)
			return
		}
		showCheck := row.Hovered() && n.Delay != DelayTesting
		if showCheck {
			mygoui.Text(c, "选择").FontSize(12).TextColor(pal.Primary)
		} else if n.Delay >= 0 {
			mygoui.Text(c, DelayText(n.Delay, DelayTimeout)).FontSize(14).TextColor(pal.Color(DelayTone(n.Delay, DelayTimeout)))
		} else if selected {
			mygoui.Text(c, "✓").FontSize(14).TextColor(pal.Primary)
		} else {
			mygoui.Text(c, DelayText(n.Delay, DelayTimeout)).FontSize(13).TextColor(pal.TextMuted)
		}
	})
	if row.Clicked() {
		if m.Chain.On {
			m.addChain(g, n)
			return
		}
		if SelectableGroup(g.Type) {
			m.selectNode(g, n)
		}
	}
}

func (m *Model) selectNode(g *ProxyGroup, n ProxyNode) {
	if g == nil {
		return
	}
	prevNow := g.Now
	prevNode := m.Home.Node
	g.Now = n.Name
	if m.Home.Node.Group == g.Name || m.Home.Node.Group == "" {
		m.Home.Node.Name = n.Name
		m.Home.Node.Type = n.Type
		m.Home.Node.Delay = n.Delay
		m.Home.Node.Group = g.Name
	}
	if !SelectableGroup(g.Type) || m.Hooks.SelectProxy == nil {
		return
	}
	if err := m.Hooks.SelectProxy(g.Name, n.Name); err != nil {
		g.Now = prevNow
		m.Home.Node = prevNode
		m.Notice = err.Error()
	}
}

func (m *Model) addChain(g *ProxyGroup, n ProxyNode) {
	if m.Chain.Connected || m.Chain.Connecting {
		m.Notice = "请先断开代理链再编辑节点"
		return
	}
	if g == nil || n.Preset {
		m.Notice = "请选择实际代理节点"
		return
	}
	for _, cur := range m.Chain.Nodes {
		if cur.Name == n.Name && cur.Provider == n.Provider {
			m.Notice = "该节点已在链式代理表中"
			return
		}
	}
	n.SourceGroup = g.Name
	if SelectableGroup(g.Type) {
		m.Chain.Target = g.Name
	}
	if m.Chain.Target == "" {
		for _, candidate := range m.Groups {
			if !candidate.Hidden && SelectableGroup(candidate.Type) {
				m.Chain.Target = candidate.Name
				break
			}
		}
	}
	if m.Home.Mode == "global" {
		m.Chain.Target = "GLOBAL"
	}
	m.Chain.Nodes = append(m.Chain.Nodes, n)
}
