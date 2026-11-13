package ui

import (
	"runtime"

	mygoui "github.com/egoist/mygo/ui"
)

func (m *Model) overlay(c *mygoui.Context, pal Palette) {
	if m.Dialogs.Ports && !m.portsDraftActive {
		m.portsDraft = m.Prefs
		m.portsDraftActive = true
	}
	if m.Dialogs.Hotkey && !m.hotkeyDraftActive {
		m.hotkeyDraft = m.Prefs
		m.hotkeyDraftActive = true
	}
	m.homeSettingsDialog(c, pal)
	m.chainDialog(c, pal)
	m.deleteDialog(c, pal)
	m.batchDeleteDialog(c, pal)
	m.ruleEditorDialog(c, pal)
	m.updateDialog(c, pal)
	m.profileForm(c, pal)
	m.providerDialog(c, pal)
	m.simpleDialog(c, pal, &m.Dialogs.Theme, "主题设置", m.themeBody)
	m.simpleDialog(c, pal, &m.Dialogs.Layout, "界面设置", m.layoutBody)
	m.simpleDialog(c, pal, &m.Dialogs.Misc, "杂项设置", m.miscBody)
	m.simpleDialog(c, pal, &m.Dialogs.Hotkey, "热键设置", m.hotkeyBody)
	if !m.Dialogs.Hotkey {
		m.hotkeyDraftActive = false
	}
	m.simpleDialog(c, pal, &m.Dialogs.Backup, "备份设置", m.backupBody)
	m.simpleDialog(c, pal, &m.Dialogs.Ports, "端口设置", m.portsBody)
	if !m.Dialogs.Ports {
		m.portsDraftActive = false
	}
	m.simpleDialog(c, pal, &m.Dialogs.Sysproxy, "系统代理设置", m.sysproxyBody)
	m.simpleDialog(c, pal, &m.Dialogs.TUN, "TUN 设置", m.tunBody)
	m.serviceDialog(c, pal)
	m.simpleDialog(c, pal, &m.Dialogs.DNS, "DNS 覆写", m.dnsBody)
	m.simpleDialog(c, pal, &m.Dialogs.Runtime, "当前配置", m.runtimeBody)
	m.simpleDialog(c, pal, &m.Dialogs.Lite, "轻量模式设置", m.liteBody)
	m.simpleDialog(c, pal, &m.Dialogs.WebDAV, "WebDAV", m.webdavBody)
	m.dnsConfirm(c, pal)
	m.connColumnDialog(c, pal)
	m.ruleProviderDialog(c, pal)
	m.testFormDialog(c, pal)
}

func (m *Model) batchDeleteDialog(c *mygoui.Context, pal Palette) {
	if !m.BatchDeleteAsk {
		return
	}
	mygoui.Modal(c, &m.BatchDeleteAsk, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(10).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "删除选中订阅？").FontSize(18).Bold()
			mygoui.Text(c, "当前使用中的订阅会保留，其余选中项将被删除。").FontSize(14)
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "取消", "batch-delete-cancel", false) {
					m.BatchDeleteAsk = false
				}
				if filledButton(c, pal, "确认删除", "batch-delete-confirm", true) {
					m.BatchDeleteAsk = false
					m.deleteChecked()
				}
			})
		})
	})
}

func (m *Model) homeSettingsDialog(c *mygoui.Context, pal Palette) {
	if !m.HomeEdit {
		return
	}
	mygoui.Modal(c, &m.HomeEdit, func() {
		mygoui.Column(c).Width(360).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "首页设置").FontSize(18).Bold()
			boxes := []struct {
				label string
				on    *bool
			}{
				{"订阅卡", &m.Draft.Profile},
				{"当前代理卡", &m.Draft.Proxy},
				{"网络设置卡", &m.Draft.Network},
				{"代理模式卡", &m.Draft.Mode},
				{"流量统计卡", &m.Draft.Traffic},
				{"网站测试卡", &m.Draft.Test},
				{"IP 信息卡", &m.Draft.IP},
				{"Clash 信息卡", &m.Draft.ClashInfo},
				{"系统信息卡", &m.Draft.SystemInfo},
			}
			for _, b := range boxes {
				mygoui.Checkbox(c, b.on, b.label)
			}
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "取消", "home-cancel", false) {
					m.HomeEdit = false
				}
				if filledButton(c, pal, "保存", "home-save", true) {
					m.Cards = m.Draft
					m.HomeEdit = false
				}
			})
		})
	})
}

func (m *Model) chainDialog(c *mygoui.Context, pal Palette) {
	if !m.Chain.Ask {
		return
	}
	open := true
	mygoui.Modal(c, &open, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "链式代理").FontSize(18).Bold()
			mygoui.Text(c, "链式代理会显著降低网速。如果您没有明确的业务需求，或不了解此项配置，请保持关闭").FontSize(14)
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "保持关闭", "chain-keep", false) {
					m.Chain.Ask = false
				}
				if filledButton(c, pal, "我明白，开启", "chain-enable", true) {
					m.Chain.Ask = false
					m.Chain.On = true
				}
			})
		})
	})
	if !open {
		m.Chain.Ask = false
	}
}

func (m *Model) deleteDialog(c *mygoui.Context, pal Palette) {
	if m.DeleteUID == "" {
		return
	}
	open := true
	mygoui.Modal(c, &open, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "确认删除").FontSize(18).Bold()
			mygoui.Text(c, "此操作不可逆").FontSize(14)
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "取消", "delete-cancel", false) {
					m.DeleteUID = ""
				}
				if filledButton(c, pal, "确认", "delete-ok", true) {
					uid := m.DeleteUID
					m.DeleteUID = ""
					if m.Hooks.DeleteProfile != nil {
						if err := m.Hooks.DeleteProfile(uid); err != nil {
							m.Notice = err.Error()
						} else {
							m.Notice = "订阅已删除"
						}
						return
					}
					var keep []ProfileItem
					for _, p := range m.Profiles {
						if p.UID != uid {
							keep = append(keep, p)
						}
					}
					m.Profiles = keep
					if m.CurrentProfile == uid {
						m.CurrentProfile = ""
						m.Home.Profile = nil
					}
					m.Notice = "订阅已删除"
				}
			})
		})
	})
	if !open {
		m.DeleteUID = ""
	}
}

func (m *Model) profileForm(c *mygoui.Context, pal Palette) {
	if !m.Form.Open {
		return
	}
	mygoui.Modal(c, &m.Form.Open, func() {
		title := "新建配置"
		if m.Form.Editing {
			title = "编辑配置"
		}
		mygoui.Column(c).Width(375).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, title).FontSize(18).Bold()
			if m.Hooks.SaveProfileMetadata == nil {
				types := []string{"远程", "本地"}
				cur := "远程"
				if m.Form.Type == "local" {
					cur = "本地"
				}
				mygoui.Text(c, "类型").FontSize(13).TextColor(pal.TextMuted)
				sel := mygoui.Select(c, &cur, types).FillWidth().Label("profile-type")
				if sel.Changed() {
					if cur == "本地" {
						m.Form.Type = "local"
					} else {
						m.Form.Type = "remote"
					}
				}
			}
			m.field(c, "名称", &m.Form.Name)
			m.field(c, "描述", &m.Form.Desc)
			if m.Form.Type == "remote" && !m.Form.Editing {
				m.field(c, "订阅链接", &m.Form.URL)
			}
			if m.Form.Type == "remote" && m.Hooks.SaveProfileMetadata != nil {
				m.field(c, "用户代理（留空使用默认值）", &m.Form.UA)
				mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Gap(8).Children(func() {
					mygoui.Text(c, "下载超时（秒）").FontSize(13).Grow(1)
					timeout := itoa(m.Form.Timeout)
					if mygoui.TextInput(c, &timeout).Width(100).Label("subscription-timeout").Changed() {
						m.Form.Timeout = atoi(timeout)
					}
				})
				m.boolLine(c, "通过内核代理下载和更新", &m.Form.Clash)
				m.boolLine(c, "允许无效证书（不安全）", &m.Form.Insecure)
				if m.Form.SysProxy {
					m.boolLine(c, "使用系统代理（尚不支持，请关闭）", &m.Form.SysProxy)
				}
				m.boolLine(c, "自动更新订阅", &m.Form.Auto)
				mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Gap(8).Children(func() {
					mygoui.Text(c, "更新间隔（分钟）").FontSize(13).Grow(1)
					interval := itoa(m.Form.Interval)
					if mygoui.TextInput(c, &interval).Width(100).Label("auto-update-interval").Changed() {
						m.Form.Interval = atoi(interval)
					}
				})
				if FrequentUpdate(m.Form.Interval) {
					mygoui.Text(c, "频繁更新会增加网络请求并可能重载内核。").FontSize(12).TextColor(pal.Warning)
				}
			}
			if m.Form.Type == "remote" && m.Hooks.SaveProfileMetadata == nil {
				m.field(c, "用户代理", &m.Form.UA)
				mygoui.Text(c, "更新间隔").FontSize(13)
				interval := itoa(m.Form.Interval)
				in := mygoui.TextInput(c, &interval).Label("interval")
				if in.Changed() {
					m.Form.Interval = atoi(interval)
				}
				mygoui.Text(c, "分钟").FontSize(12).TextColor(pal.TextMuted)
				if FrequentUpdate(m.Form.Interval) {
					mygoui.Text(c, "间隔过短会频繁触发内核重载并中断现有连接，建议使用默认值 1440 分钟（24 小时）").FontSize(12).TextColor(pal.Warning)
				}
				m.boolLine(c, "使用系统代理更新", &m.Form.SysProxy)
				m.boolLine(c, "使用内核代理更新", &m.Form.Clash)
				m.boolLine(c, "允许无效证书（危险）", &m.Form.Insecure)
				m.boolLine(c, "允许自动更新", &m.Form.Auto)
			}
			if m.Form.Error != "" {
				mygoui.Text(c, m.Form.Error).TextColor(pal.Error).FontSize(12)
			}
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "取消", "form-cancel", false) {
					m.Form.Open = false
				}
				if filledButton(c, pal, "保存", "form-save", true) && !m.ProfileBusy {
					m.saveForm()
				}
			})
		})
	})
}

func (m *Model) saveForm() {
	if m.Hooks.SaveProfileMetadata != nil && m.Form.Editing {
		if err := m.Hooks.SaveProfileMetadata(m.Form); err != nil {
			m.Form.Error = err.Error()
			return
		}
		m.Form.Open = false
		m.Notice = "订阅信息已保存"
		return
	}
	if m.Hooks.CreateProfileAsync != nil && !m.Form.Editing {
		if !ValidSubscriptionURL(m.Form.URL) {
			m.Form.Error = "请输入有效的订阅链接"
			return
		}
		if m.Form.Interval < 1 || m.Form.Interval > 43200 {
			m.Form.Error = "更新间隔必须在 1 到 43200 分钟之间"
			return
		}
		form := m.Form
		m.ProfileBusy = true
		m.Form.Error = "正在下载订阅…"
		m.Hooks.CreateProfileAsync(form, func(err error) {
			m.ProfileBusy = false
			if err != nil {
				m.Form.Error = err.Error()
				return
			}
			m.Form.Open = false
			m.Notice = "订阅已导入"
		})
		return
	}
	if m.Hooks.ImportURL != nil {
		m.Form.Error = "当前无法创建订阅"
		return
	}
	if m.Form.Type == "" {
		m.Form.Error = "请选择订阅类型"
		return
	}
	if m.Form.Type == "remote" && !ValidSubscriptionURL(m.Form.URL) {
		m.Form.Error = "请输入订阅链接"
		return
	}
	if m.Form.Editing && m.Form.UID == "" {
		m.Form.Error = "缺少订阅标识"
		return
	}
	item := ProfileItem{
		UID: m.Form.UID, Name: m.Form.Name, Description: m.Form.Desc, URL: m.Form.URL, Type: m.Form.Type,
		Option: ProfileOption{
			UpdateInterval: m.Form.Interval, UseSystemProxy: m.Form.SysProxy, UseClashProxy: m.Form.Clash,
			AcceptInvalid: m.Form.Insecure, AllowAutoUpdate: m.Form.Auto, UserAgent: m.Form.UA, TimeoutSeconds: m.Form.Timeout,
		},
	}
	if item.Name == "" {
		item.Name = "未命名"
	}
	if m.Form.Editing {
		for i := range m.Profiles {
			if m.Profiles[i].UID == item.UID {
				item.Updated = m.Profiles[i].Updated
				m.Profiles[i] = item
			}
		}
	} else {
		m.addProfile(item)
	}
	m.Form.Open = false
	m.Notice = "保存成功"
}

func (m *Model) field(c *mygoui.Context, label string, value *string) {
	mygoui.Text(c, label).FontSize(13)
	mygoui.TextInput(c, value).FillWidth().Label("field-" + label)
}

func (m *Model) boolLine(c *mygoui.Context, label string, on *bool) {
	mygoui.Row(c).AlignItems(mygoui.Center).Children(func() {
		mygoui.Text(c, label).FontSize(14).Grow(1)
		mygoui.Switch(c, on)
	})
}

func (m *Model) providerDialog(c *mygoui.Context, pal Palette) {
	if !m.Dialogs.Provider {
		return
	}
	mygoui.Modal(c, &m.Dialogs.Provider, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "代理集合").FontSize(18).Bold()
			if len(m.Providers) == 0 {
				mygoui.Text(c, "没有可更新的 provider").TextColor(pal.TextMuted)
			}
			for i := range m.Providers {
				p := &m.Providers[i]
				mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
					mygoui.Text(c, p.Name).FontSize(14).Grow(1)
					chip(c, pal, p.Type, ToneMuted, false)
					mygoui.Text(c, itoa(p.Count)+" 个节点").FontSize(12).TextColor(pal.TextMuted)
					if textButton(c, pal, "更新", "更新", "prov-"+p.Name) {
						m.updateProxyProviders([]string{p.Name})
					}
				})
			}
			if filledButton(c, pal, "更新全部", "prov-all", true) {
				var names []string
				for _, p := range m.Providers {
					names = append(names, p.Name)
				}
				m.updateProxyProviders(names)
			}
		})
	})
}

func (m *Model) simpleDialog(c *mygoui.Context, pal Palette, open *bool, title string, body func(*mygoui.Context, Palette)) {
	if open == nil || !*open {
		return
	}
	mygoui.Modal(c, open, func() {
		mygoui.Column(c).Width(440).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, title).FontSize(18).Bold()
			if body != nil {
				body(c, pal)
			}
			if filledButton(c, pal, "关闭", "close-"+title, false) {
				*open = false
			}
		})
	})
	if !*open && (title == "主题设置" || title == "界面设置" || title == "杂项设置") {
		m.savePrefs()
	}
}

func (m *Model) themeBody(c *mygoui.Context, pal Palette) {
	dark := pal.Dark
	rows := []struct {
		label, placeholder string
		value              *string
	}{
		{"主要颜色", DefaultPrimary(dark), &m.Prefs.ThemePrimary},
		{"次要颜色", DefaultSecondary(dark), &m.Prefs.ThemeSecondary},
		{"文本主要颜色", DefaultPrimaryText(dark), &m.Prefs.ThemeText},
		{"文本次要颜色", DefaultSecondaryText(dark), &m.Prefs.ThemeMuted},
		{"信息颜色", DefaultInfo(dark), &m.Prefs.ThemeInfo},
		{"警告颜色", DefaultWarning(dark), &m.Prefs.ThemeWarning},
		{"错误颜色", DefaultError(dark), &m.Prefs.ThemeError},
		{"成功颜色", DefaultSuccess(dark), &m.Prefs.ThemeSuccess},
	}
	for _, row := range rows {
		shown := row.placeholder
		if *row.value != "" {
			shown = *row.value
		}
		mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
			mygoui.Box(c).Size(18, 18).Radius(4).Background(mygoui.Hex(safeHex(shown)))
			mygoui.Text(c, row.label).FontSize(13).Grow(1)
			mygoui.TextInput(c, row.value).Width(135).Placeholder(row.placeholder)
		})
	}
	m.field(c, "字体系列", &m.Prefs.FontFamily)
	mygoui.Text(c, "字体包含 "+FontStack).FontSize(11).TextColor(pal.TextMuted)
}

func safeHex(s string) string {
	if !validHex(s) {
		return "#007AFF"
	}
	return s
}

func validHex(s string) bool {
	if len(s) != 7 && len(s) != 9 || len(s) == 0 || s[0] != '#' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func (m *Model) layoutBody(c *mygoui.Context, pal Palette) {
	m.boolLine(c, "流量图显", &m.Prefs.TrafficGraph)
	m.boolLine(c, "内核占用", &m.Prefs.MemoryUsage)
	m.boolLine(c, "代理组图标", &m.Prefs.GroupIcon)
	m.boolLine(c, "失去焦点时暂停渲染流量统计", &m.Prefs.PauseOnBlur)
	m.boolLine(c, "悬浮跳转导航", &m.Prefs.HoverNav)
	m.boolLine(c, "收起导航栏", &m.Prefs.CollapseNav)
	mygoui.Text(c, "悬浮跳转导航延迟").FontSize(13)
	delay := itoa(m.Prefs.HoverDelay)
	in := mygoui.TextInput(c, &delay).Width(120).Label("hover-delay")
	if in.Changed() {
		m.Prefs.HoverDelay = atoi(delay)
		if m.Prefs.HoverDelay < 0 {
			m.Prefs.HoverDelay = 0
		}
		if m.Prefs.HoverDelay > 5000 {
			m.Prefs.HoverDelay = 5000
		}
	}
	mygoui.Text(c, "毫秒").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "默认 280").FontSize(12).TextColor(pal.TextMuted)
}

func (m *Model) miscBody(c *mygoui.Context, pal Palette) {
	col := "自动"
	if m.Prefs.ProxyColumns >= 1 && m.Prefs.ProxyColumns <= 5 {
		col = itoa(m.Prefs.ProxyColumns)
	}
	opts := []string{"自动", "1", "2", "3", "4", "5"}
	mygoui.Text(c, "代理列数").FontSize(13)
	sel := mygoui.Select(c, &col, opts).Width(160).Label("proxy-cols")
	if sel.Changed() {
		if col == "自动" {
			m.Prefs.ProxyColumns = AutoProxyColumns
		} else {
			m.Prefs.ProxyColumns = atoi(col)
		}
	}
	mygoui.Text(c, "内部值 "+itoa(m.Prefs.ProxyColumns)).FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "默认延迟测试").FontSize(13)
	url := "http://cp.cloudflare.com/generate_204"
	mygoui.Text(c, url).FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "默认超时 10000").FontSize(12).TextColor(pal.TextMuted)
}

func (m *Model) hotkeyBody(c *mygoui.Context, pal Palette) {
	p := &m.hotkeyDraft
	rows := []struct {
		label string
		value *string
	}{
		{"打开面板", &p.HotkeyDash},
		{"规则模式", &p.HotkeyRule},
		{"全局模式", &p.HotkeyGlobal},
		{"直连模式", &p.HotkeyDirect},
		{"切换系统代理", &p.HotkeyProxy},
		{"切换 TUN 模式", &p.HotkeyTUN},
		{"轻量模式", &p.HotkeyLite},
		{"重新激活订阅", &p.HotkeyProfiles},
	}
	for _, row := range rows {
		mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
			mygoui.Text(c, row.label).FontSize(13).Grow(1)
			mygoui.TextInput(c, row.value).Width(180).Placeholder("未设置")
		})
	}
	mygoui.Text(c, "例如 Ctrl+Shift+K；留空表示不注册。").FontSize(12).TextColor(pal.TextMuted)
	if filledButton(c, pal, "保存快捷键", "hotkeys-save", true) {
		if m.Hooks.ApplyHotkeys != nil {
			if err := m.Hooks.ApplyHotkeys(*p); err != nil {
				m.Notice = err.Error()
				return
			}
		}
		m.Prefs.HotkeyDash = p.HotkeyDash
		m.Prefs.HotkeyRule = p.HotkeyRule
		m.Prefs.HotkeyGlobal = p.HotkeyGlobal
		m.Prefs.HotkeyDirect = p.HotkeyDirect
		m.Prefs.HotkeyProxy = p.HotkeyProxy
		m.Prefs.HotkeyTUN = p.HotkeyTUN
		m.Prefs.HotkeyLite = p.HotkeyLite
		m.Prefs.HotkeyProfiles = p.HotkeyProfiles
		if m.Hooks.ApplyHotkeys == nil {
			m.savePrefs()
		}
		m.Dialogs.Hotkey = false
		m.Notice = "快捷键已保存"
	}
}

func (m *Model) backupBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "自动备份").FontSize(16).Bold()
	m.boolLine(c, "启用定时备份", &m.Prefs.AutoBackup)
	mygoui.Text(c, "按设定频率在后台创建本地备份文件。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "备份频率").FontSize(13)
	every := itoa(m.Prefs.BackupEvery)
	in := mygoui.TextInput(c, &every).Width(80).Disabled(!m.Prefs.AutoBackup).Label("backup-every")
	if in.Changed() {
		n := atoi(every)
		if n < 1 {
			n = 1
		}
		if n > 168 {
			n = 168
		}
		m.Prefs.BackupEvery = n
	}
	mygoui.Text(c, "小时，默认 24，范围 1–168").FontSize(12).TextColor(pal.TextMuted)
	m.boolLine(c, "关键变更时自动备份", &m.Prefs.BackupOnChange)
	mygoui.Text(c, "手动").FontSize(16).Bold()
	mygoui.Text(c, "本地备份").FontSize(13)
	if filledButton(c, pal, "配置 WebDAV", "webdav-open", false) {
		m.Dialogs.WebDAV = true
	}
}

func (m *Model) webdavBody(c *mygoui.Context, pal Palette) {
	m.field(c, "WebDAV 地址", &m.Prefs.WebDAVURL)
	m.field(c, "用户名", &m.Prefs.WebDAVUser)
	m.field(c, "密码", &m.Prefs.WebDAVPassword)
	if filledButton(c, pal, "保存", "webdav-save", true) {
		m.savePrefs()
		m.Notice = "保存成功"
	}
}

func (m *Model) portsBody(c *mygoui.Context, pal Palette) {
	p := &m.portsDraft
	m.portLine(c, "混合代理端口", &p.MixedPort, nil)
	m.portLine(c, "SOCKS 代理端口", &p.SocksPort, &p.SocksOn)
	m.portLine(c, "HTTP(S) 代理端口", &p.HTTPPort, &p.HTTPOn)
	if runtime.GOOS != "windows" {
		m.portLine(c, "Redir 透明代理端口", &p.RedirPort, &p.RedirOn)
	}
	if runtime.GOOS == "linux" {
		m.portLine(c, "Tproxy 透明代理端口", &p.TProxyPort, &p.TProxyOn)
	}
	ports := PortSet{
		Mixed: p.MixedPort, Socks: p.SocksPort, SocksOn: p.SocksOn,
		HTTP: p.HTTPPort, HTTPOn: p.HTTPOn, Redir: p.RedirPort, RedirOn: p.RedirOn,
		TProxy: p.TProxyPort, TProxyOn: p.TProxyOn,
		ShowRedir: runtime.GOOS != "windows", ShowTProxy: runtime.GOOS == "linux",
	}
	err := ValidatePorts(ports)
	if err != "" {
		mygoui.Text(c, err).FontSize(12).TextColor(pal.Error)
	}
	if filledButton(c, pal, "保存", "ports-save", true) {
		if err != "" {
			m.Notice = err
			return
		}
		if m.Hooks.SetKernelPorts != nil {
			if applyErr := m.Hooks.SetKernelPorts(ports); applyErr != nil {
				m.Notice = applyErr.Error()
				return
			}
		}
		if m.Hooks.SetKernelPorts == nil {
			m.Prefs.MixedPort = p.MixedPort
			m.Prefs.SocksPort = p.SocksPort
			m.Prefs.SocksOn = p.SocksOn
			m.Prefs.HTTPPort = p.HTTPPort
			m.Prefs.HTTPOn = p.HTTPOn
		}
		m.Home.MixedPort = p.MixedPort
		m.Notice = "端口设置已保存"
		m.Dialogs.Ports = false
	}
	_ = pal
}

func (m *Model) portLine(c *mygoui.Context, label string, port *int, on *bool) {
	text := itoa(*port)
	mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
		mygoui.Text(c, label).FontSize(13).Grow(1)
		if on != nil {
			mygoui.Switch(c, on)
		}
		in := mygoui.TextInput(c, &text).Width(80).Label("port-" + label)
		if in.Changed() {
			*port = atoi(text)
		}
		if textButton(c, PaletteFor(false), "随机", "随机端口", "rand-"+label) {
			*port = 20000 + len(label)*97%40000
		}
	})
}

func (m *Model) sysproxyBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "当前状态").FontSize(14).Bold()
	state := "未启用"
	if m.Home.SystemProxy {
		state = "已启用"
	}
	mygoui.Text(c, "启用状态 "+state).FontSize(13)
	mygoui.Text(c, "服务器地址 "+m.proxyAddr()).FontSize(13)
	mygoui.Text(c, "绕过 127.0.0.1, localhost, *.local").FontSize(12).TextColor(pal.TextMuted)
}

func (m *Model) tunBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "栈").FontSize(13)
	if m.TunStack == "" {
		m.TunStack = "Mips"
	}
	mygoui.Select(c, &m.TunStack, []string{"System", "gVisor", "Mixed", "Mips"}).Label("tun-stack")
	mygoui.Text(c, "DNS").FontSize(13)
	dns := "Auto"
	mygoui.Select(c, &dns, []string{"Auto", "Disabled", "Native", "Hijack"}).Label("tun-dns")
	mygoui.Text(c, "设备").FontSize(13)
	dev := "utun"
	mygoui.TextInput(c, &dev)
	_ = pal
}

func (m *Model) serviceDialog(c *mygoui.Context, pal Palette) {
	if !m.Dialogs.Service {
		return
	}
	mygoui.Modal(c, &m.Dialogs.Service, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "服务模式").FontSize(18).Bold()
			state := "未安装"
			if m.ServiceInstalled {
				state = "已安装"
			}
			mygoui.Text(c, "当前状态："+state).FontSize(14)
			mygoui.Text(c, "安装服务后，内核由服务拉起，即可使用 TUN。未安装时无法开启虚拟网卡。").FontSize(13).TextColor(pal.TextMuted)
			mygoui.Row(c).Gap(8).Justify(mygoui.End).Children(func() {
				if !m.ServiceInstalled && filledButton(c, pal, "安装服务", "service-install", true) {
					m.installService()
				}
				if m.ServiceInstalled && filledButton(c, pal, "卸载服务", "service-uninstall", false) {
					m.uninstallService()
				}
				if textButton(c, pal, "关闭", "关闭", "service-close") {
					m.Dialogs.Service = false
				}
			})
		})
	})
}

func (m *Model) installService() {
	m.Busy = "service"
	defer func() { m.Busy = "" }()
	if m.Hooks.InstallService == nil {
		m.Notice = "安装服务失败"
		return
	}
	if err := m.Hooks.InstallService(); err != nil {
		m.Notice = "安装服务失败"
		return
	}
	m.ServiceInstalled = true
	m.Home.TUNAvailable = true
	m.Home.RunMode = RunService
	m.Notice = "已成功安装服务"
}

func (m *Model) uninstallService() {
	m.Busy = "service"
	defer func() { m.Busy = "" }()
	if m.Hooks.UninstallService == nil {
		m.Notice = "卸载服务失败"
		return
	}
	if err := m.Hooks.UninstallService(); err != nil {
		m.Notice = "卸载服务失败"
		return
	}
	m.ServiceInstalled = false
	m.ServiceRunning = false
	if m.Home.RunMode == RunService {
		m.Home.RunMode = RunSidecar
	}
	m.Notice = "已成功卸载服务"
}

func (m *Model) dnsBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "DNS 覆写开关按订阅独立保存，仅对对应订阅生效。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "如果你不清楚这里的设置请不要修改，并保持 DNS 覆写关闭").FontSize(12).TextColor(pal.Warning)
	mygoui.Text(c, "DNS 设置").FontSize(14).Bold()
	mygoui.Text(c, "listen :53").FontSize(13)
	mygoui.Text(c, "fake-ip-range 198.18.0.1/16").FontSize(13)
	mygoui.Text(c, "回退过滤设置").FontSize(14).Bold()
	mygoui.Text(c, "Hosts 设置").FontSize(14).Bold()
}

func (m *Model) runtimeBody(c *mygoui.Context, pal Palette) {
	chip(c, pal, "只读", ToneMuted, false)
	mygoui.Text(c, "无法在只读模式下编辑").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "mode: "+m.Home.Mode).FontSize(13)
	mygoui.Text(c, "mixed-port: "+itoa(nonZero(m.Home.MixedPort, 7897))).FontSize(13)
}

func (m *Model) liteBody(c *mygoui.Context, pal Palette) {
	if filledButton(c, pal, "立即进入", "lite-now", true) {
		m.setLightweight(true)
	}
	mygoui.Text(c, "隐藏主窗口并保持代理运行；可通过托盘重新打开。\n需要启动时隐藏窗口，可在系统设置中开启静默启动。 ").FontSize(12).TextColor(pal.TextMuted)
}

func (m *Model) dnsConfirm(c *mygoui.Context, pal Palette) {
	if !m.DNSAsk {
		return
	}
	open := true
	mygoui.Modal(c, &open, func() {
		mygoui.Column(c).Width(420).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "是否开启 DNS 覆写？").FontSize(18).Bold()
			mygoui.Text(c, "当前订阅包含自定义 DNS 配置。开启 DNS 覆写可能覆盖这些配置，导致节点无法连接或部分网站无法访问。是否仍要开启？").FontSize(14)
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "保持关闭", "dns-keep", false) {
					m.Prefs.DNSOverwrite = false
					m.DNSAsk = false
				}
				if filledButton(c, pal, "仍然开启", "dns-anyway", true) {
					m.Prefs.DNSOverwrite = true
					m.DNSAsk = false
					m.savePrefs()
				}
			})
		})
	})
	if !open {
		m.DNSAsk = false
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
