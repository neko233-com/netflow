package ui

import (
	"runtime"

	mygoui "github.com/egoist/mygo/ui"
)

func (m *Model) settingsPage(c *mygoui.Context, pal Palette) {
	m.page(c, pal, "设置", func() {
		if textButton(c, pal, "手册", "使用手册", "set-manual") {
			c.OpenURL("https://github.com/neko233-com/netflow#readme")
		}
		if textButton(c, pal, "GitHub", "GitHub 项目地址", "set-gh") {
			c.OpenURL("https://github.com/neko233-com/netflow")
		}
	}, func() {
		mygoui.Text(c, "预览版：部分设置仅保存界面偏好，尚未作用于系统或内核。请参阅项目说明。").FontSize(13).TextColor(pal.Warning).Padding(12, 16)
		w, _ := c.Size()
		cols := 1
		if WideLayout(w) {
			cols = 2
		}
		mygoui.Grid(c).Columns(cols).Gap(12).Padding(16).Children(func() {
			mygoui.Column(c).Gap(12).Children(func() {
				m.systemSettings(c, pal)
				m.clashSettings(c, pal)
			})
			mygoui.Column(c).Gap(12).Children(func() {
				m.vergeBasic(c, pal)
				m.vergeAdvanced(c, pal)
			})
		})
	})
}

func (m *Model) systemSettings(c *mygoui.Context, pal Palette) {
	sectionCard(c, pal, "系统设置", func() {
		tunOn := m.Home.TUN
		m.switchLine(c, pal, "虚拟网卡模式", &tunOn, "tun-row", func(on bool) { m.setTUN(on) }, func() {
			if !m.Home.TUNAvailable {
				mygoui.Icon(c, iconWarn).Size(18, 18).TextColor(pal.Warning).Tooltip("TUN 模式需要安装服务模式或管理员模式").Label("tun-warn")
			}
			if gearButton(c, pal, "TUN", "tun-gear") {
				m.Dialogs.TUN = true
			}
		})
		proxyOn := m.Home.SystemProxy
		m.switchLine(c, pal, "系统代理", &proxyOn, "sysproxy-row", func(on bool) { m.setProxy(on) }, func() {
			if gearButton(c, pal, "系统代理", "sysproxy-gear") {
				m.Dialogs.Sysproxy = true
			}
		})
		m.switchLine(c, pal, "开机自启", &m.Prefs.AutoLaunch, "launch-row", m.setAutoLaunch, nil)
		m.switchLine(c, pal, "静默启动", &m.Prefs.SilentStart, "silent-row", func(bool) { m.savePrefs() }, func() {
			helpMark(c, pal, "help-silent", "程序启动时以后台模式运行，不显示程序面板")
		})
		status := "未安装"
		if m.ServiceInstalled {
			status = "已安装"
		}
		clickRow(c, pal, "服务模式", "service-row", m.Busy == "service", func() {
			m.Dialogs.Service = true
		}, func() {
			mygoui.Text(c, status).FontSize(14)
		})
	})
}

func (m *Model) switchLine(c *mygoui.Context, pal Palette, label string, on *bool, id string, apply func(bool), extra func()) {
	mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Gap(8).Children(func() {
		mygoui.Text(c, label).FontSize(14).Grow(1)
		if extra != nil {
			extra()
		}
		sw := mygoui.Switch(c, on).Label(id)
		if sw.Changed() && apply != nil {
			apply(*on)
		}
	})
	_ = pal
}

func (m *Model) clashSettings(c *mygoui.Context, pal Palette) {
	sectionCard(c, pal, "Clash 设置", func() {
		m.switchLine(c, pal, "局域网连接", &m.Prefs.AllowLan, "allow-lan", func(on bool) { m.setKernelBool("allow-lan", &m.Prefs.AllowLan, on) }, func() {
			if gearButton(c, pal, "网络接口", "lan-gear") {
				m.Notice = "网络接口"
			}
		})
		disabled := m.currentProfile() == nil || m.DNSAsk
		mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Gap(8).Children(func() {
			mygoui.Text(c, "DNS 覆写").FontSize(14).Grow(1)
			helpMark(c, pal, "help-dns", "DNS 覆写开关按订阅独立保存，仅对对应订阅生效。")
			if gearButton(c, pal, "DNS 覆写", "dns-gear") {
				if p := m.currentProfile(); p != nil {
					m.DNSDraft = p.Option.DNSOverride
					m.DNSProfileID = p.UID
					m.Dialogs.DNS = true
				} else {
					m.Notice = "请先激活订阅"
				}
			}
			sw := mygoui.Switch(c, &m.Prefs.DNSOverwrite).Disabled(disabled).Label("dns-overwrite")
			if sw.Changed() {
				p := m.currentProfile()
				if p == nil || m.Hooks.SetProfileDNS == nil {
					m.Prefs.DNSOverwrite = !m.Prefs.DNSOverwrite
					m.Notice = "DNS 覆写不可用"
					return
				}
				if m.Prefs.DNSOverwrite && p.Option.DNSOverride == "" {
					m.Prefs.DNSOverwrite = false
					m.DNSDraft = ""
					m.DNSProfileID = p.UID
					m.Dialogs.DNS = true
					m.Notice = "请先填写 DNS 配置"
					return
				}
				if err := m.Hooks.SetProfileDNS(p.UID, m.Prefs.DNSOverwrite, p.Option.DNSOverride); err != nil {
					m.Prefs.DNSOverwrite = !m.Prefs.DNSOverwrite
					m.Notice = err.Error()
				}
			}
		})
		m.switchLine(c, pal, "IPv6", &m.Prefs.IPv6, "ipv6", func(on bool) { m.setKernelBool("ipv6", &m.Prefs.IPv6, on) }, nil)
		m.switchLine(c, pal, "统一延迟", &m.Prefs.UnifiedDelay, "unified", func(on bool) { m.setKernelBool("unified-delay", &m.Prefs.UnifiedDelay, on) }, func() {
			helpMark(c, pal, "help-unified", "开启统一延迟时，会进行两次延迟测试，以消除连接握手等带来的不同类型节点的延迟差异")
		})
		mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Children(func() {
			mygoui.Text(c, "日志等级").FontSize(14).Grow(1)
			previous := m.Prefs.LogLevel
			if mygoui.Select(c, &m.Prefs.LogLevel, []string{"debug", "info", "warning", "error", "silent"}).Width(120).Label("log-level").Changed() {
				if m.Hooks.SetKernelOption != nil {
					if err := m.Hooks.SetKernelOption("log-level", m.Prefs.LogLevel); err != nil {
						m.Prefs.LogLevel = previous
						m.Notice = err.Error()
					}
				}
			}
		})
		clickRow(c, pal, "端口设置", "ports", m.Busy == "ports", func() { m.Dialogs.Ports = true }, func() {
			mygoui.Text(c, itoa(m.Prefs.MixedPort)).FontSize(13).TextColor(pal.TextMuted)
		})
		clickRow(c, pal, "外部控制", "external", false, func() { m.Notice = "外部控制器监听地址" }, func() {
			if textButton(c, pal, "CORS", "外部控制跨域设置", "cors") {
				m.Notice = "外部控制跨域设置"
			}
		})
		clickRow(c, pal, "网页界面", "webui", false, func() { m.Notice = "网页界面" }, nil)
		clickRow(c, pal, "Clash 内核", "core-row", false, func() { m.Dialogs.Lite = false }, func() {
			mygoui.Text(c, orDash(m.Home.Version)).FontSize(13)
			if gearButton(c, pal, "Clash 内核", "core-gear") {
				m.Notice = "Clash 内核 " + orDash(m.Home.Version)
			}
		})
		if runtime.GOOS == "windows" {
			clickRow(c, pal, "UWP 工具", "uwp", false, func() {}, nil)
		}
		clickRow(c, pal, "更新 GeoData", "geo", m.Busy == "geo", func() {
			m.Notice = "GeoData 更新尚未实现"
		}, nil)
		clickRow(c, pal, "流量隧道管理", "tunnels", false, func() { m.Notice = "流量隧道管理" }, nil)
	})
}

func (m *Model) setKernelBool(name string, field *bool, on bool) {
	if m.Hooks.SetKernelOption != nil {
		if err := m.Hooks.SetKernelOption(name, on); err != nil {
			*field = !on
			m.Notice = err.Error()
		}
	}
}

func (m *Model) vergeBasic(c *mygoui.Context, pal Palette) {
	sectionCard(c, pal, "Verge 基础设置", func() {
		names := make([]string, len(Languages()))
		for i, l := range Languages() {
			names[i] = l.Name
		}
		cur := LanguageName(m.Prefs.Language)
		mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Children(func() {
			mygoui.Text(c, "语言设置").FontSize(14).Grow(1)
			sel := mygoui.Select(c, &cur, names).Width(140).Label("language")
			if sel.Changed() {
				m.Prefs.Language = LanguageID(cur)
				m.savePrefs()
			}
		})
		mygoui.Text(c, "主题模式").FontSize(14)
		segmentButtons(c, pal, "theme", []struct{ id, label string }{
			{"light", "浅色"}, {"dark", "深色"}, {"system", "系统"},
		}, m.Prefs.ThemeMode, func(id string) {
			m.Prefs.ThemeMode = id
			m.savePrefs()
		})
		if runtime.GOOS != "linux" || m.ForceTray {
			m.choiceRow(c, "托盘点击事件", &m.Prefs.TrayEvent, TrayEvents(), "tray-event")
		}
		envs := CopyEnvTypes()
		mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Padding(5, 0).Children(func() {
			mygoui.Text(c, "复制环境变量类型").FontSize(14).Grow(1)
			sel := mygoui.Select(c, &m.Prefs.CopyEnv, envs).Width(140).Label("copy-env")
			if sel.Changed() {
				m.savePrefs()
			}
			if textButton(c, pal, "复制", "复制环境变量", "copy-env-btn") {
				m.copy(ProxyEnvironment(m.Prefs.CopyEnv, m.proxyAddr()))
			}
		})
		m.choiceRow(c, "启动页面", &m.Prefs.StartPage, StartPages(), "start-page")
		mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Gap(6).Padding(5, 0).Children(func() {
			mygoui.Text(c, "启动脚本").FontSize(14)
			mygoui.TextInput(c, &m.Prefs.StartupScript).Grow(1).ReadOnly(true).Label("startup-script")
			if filledButton(c, pal, "浏览", "browse-script", false) {
				if m.Hooks.BrowseScript != nil {
					path, err := m.Hooks.BrowseScript()
					if err != nil {
						m.Notice = err.Error()
					} else {
						m.Prefs.StartupScript = path
						m.savePrefs()
					}
				}
			}
			if m.Prefs.StartupScript != "" && textButton(c, pal, "清除", "清除", "clear-script") {
				m.Prefs.StartupScript = ""
				m.savePrefs()
			}
		})
		clickRow(c, pal, "主题设置", "theme-row", false, func() { m.Dialogs.Theme = true }, nil)
		clickRow(c, pal, "界面设置", "layout-row", false, func() { m.Dialogs.Layout = true }, nil)
		clickRow(c, pal, "杂项设置", "misc-row", false, func() { m.Dialogs.Misc = true }, nil)
		clickRow(c, pal, "热键设置", "hotkey-row", false, func() { m.Dialogs.Hotkey = true }, nil)
	})
}

func (m *Model) vergeAdvanced(c *mygoui.Context, pal Palette) {
	sectionCard(c, pal, "Verge 高级设置", func() {
		clickRow(c, pal, "备份设置", "backup", false, func() { m.Dialogs.Backup = true }, func() {
			helpMark(c, pal, "help-backup", "支持本地或 WebDAV 方式备份配置文件")
		})
		clickRow(c, pal, "当前配置", "runtime-row", false, func() { m.Dialogs.Runtime = true }, nil)
		clickRow(c, pal, "配置目录", "conf-dir", false, func() { m.openDir("config") }, func() {
			helpMark(c, pal, "help-conf", "如果软件运行异常，备份并删除此文件夹下的所有文件，重启软件")
		})
		clickRow(c, pal, "内核目录", "core-dir", false, func() { m.openDir("core") }, nil)
		clickRow(c, pal, "日志目录", "log-dir", false, func() { m.openDir("logs") }, nil)
		clickRow(c, pal, "检查更新", "check-update", m.Busy == "check-update", func() {
			m.checkUpdate()
		}, nil)
		clickRow(c, pal, "开发者工具", "devtools", false, func() { m.Notice = "开发者工具" }, nil)
		clickRow(c, pal, "轻量模式设置", "lite-row", false, func() { m.Dialogs.Lite = true }, func() {
			helpMark(c, pal, "help-lite", "关闭 GUI 界面，仅保留内核运行")
		})
		clickRow(c, pal, "退出", "quit-row", false, func() {
			if m.Hooks.Quit != nil {
				m.Hooks.Quit()
			}
			m.Notice = "退出"
		}, nil)
		clickRow(c, pal, "导出诊断信息", "diag", false, nil, func() {
			if textButton(c, pal, "复制", "导出诊断信息", "copy-diag") {
				m.copy("NetFlow " + AppVersion)
			}
		})
		ver := "v" + trimV(m.Home.VergeVersion)
		clickRow(c, pal, "NetFlow 版本", "verge-version", false, nil, func() {
			mygoui.Text(c, ver).FontSize(14)
			if textButton(c, pal, "复制", "复制 NetFlow 版本号", "copy-version") {
				m.copy(ver)
			}
		})
	})
}

func (m *Model) openDir(kind string) {
	if m.Hooks.OpenDir != nil {
		m.Hooks.OpenDir(kind)
	}
	m.Notice = "已打开目录"
}

func (m *Model) labeledSelect(c *mygoui.Context, label string, value *string, options []string, id string) {
	mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Children(func() {
		mygoui.Text(c, label).FontSize(14).Grow(1)
		sel := mygoui.Select(c, value, options).Width(120).Label(id)
		if sel.Changed() {
			m.savePrefs()
		}
	})
}

func (m *Model) choiceRow(c *mygoui.Context, label string, id *string, choices []LanguageChoice, key string) {
	names := make([]string, len(choices))
	cur := ""
	for i, ch := range choices {
		names[i] = ch.Name
		if ch.ID == *id {
			cur = ch.Name
		}
	}
	if cur == "" && len(names) > 0 {
		cur = names[0]
	}
	mygoui.Row(c).FillWidth().Padding(5, 0).AlignItems(mygoui.Center).Children(func() {
		mygoui.Text(c, label).FontSize(14).Grow(1)
		sel := mygoui.Select(c, &cur, names).Width(140).Label(key)
		if sel.Changed() {
			for _, ch := range choices {
				if ch.Name == cur {
					*id = ch.ID
				}
			}
			m.savePrefs()
		}
	})
}
