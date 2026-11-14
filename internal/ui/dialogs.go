package ui

import (
	"runtime"
	"strconv"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/neko233-com/netflow/internal/agent"
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
	m.profileQRDialog(c, pal)
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
	if !m.Dialogs.WebDAV {
		m.WebDAVURLDraft, m.WebDAVUserDraft, m.WebDAVPasswordDraft = "", "", ""
	}
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
				m.boolLine(c, "通过系统手动代理下载和更新", &m.Form.SysProxy)
				mygoui.Text(c, "不使用 PAC、自动检测或绕过列表；同时启用时优先使用内核代理。").FontSize(12).TextColor(pal.TextMuted)
				m.boolLine(c, "允许无效证书（不安全）", &m.Form.Insecure)
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
	if !*open && title == "当前配置" {
		m.RuntimeConfig = ""
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

func backupButton(c *mygoui.Context, pal Palette, label, id string, disabled bool) bool {
	b := mygoui.ButtonBase(c.Key(id)).Height(28).Padding(0, 10).Radius(6).Label(id).Disabled(disabled)
	if disabled {
		b.Background(pal.TextMuted.Alpha(0.18)).TextColor(pal.TextMuted)
	} else {
		b.Background(mygoui.Transparent).TextColor(pal.Text).Border(1, pal.Primary)
	}
	b.Children(func() { mygoui.Text(c, label).FontSize(13) })
	return b.Clicked()
}

func (m *Model) backupBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "备份包含敏感信息且未加密；恢复会写入新目录。").FontSize(12).TextColor(pal.Warning)
	mygoui.Text(c, "自动备份").FontSize(16).Bold()
	if m.BackupHours == "" {
		m.BackupHours = "24"
	}
	choices := []string{"1", "6", "12", "24", "72", "168"}
	found := false
	for _, v := range choices {
		if v == m.BackupHours {
			found = true
		}
	}
	if !found {
		choices = append(choices, m.BackupHours)
	}
	mygoui.Row(c).AlignItems(mygoui.Center).Gap(8).Children(func() {
		mygoui.Text(c, "每隔（小时）").FontSize(13)
		mygoui.Select(c, &m.BackupHours, choices).Width(80).Label("backup-every")
		if backupButton(c, pal, "选择目录并启用", "backup-auto-enable", m.BackupBusy) {
			if m.Hooks.BrowseBackupDirectory == nil || m.Hooks.SetBackupSchedule == nil {
				m.Notice = "自动备份不可用"
				return
			}
			dir, err := m.Hooks.BrowseBackupDirectory()
			if err != nil {
				m.Notice = "选择目录失败: " + err.Error()
				return
			}
			if dir == "" {
				return
			}
			hours, _ := strconv.Atoi(m.BackupHours)
			s, err := m.Hooks.SetBackupSchedule(true, dir, hours)
			if err != nil {
				m.Notice = "启用自动备份失败: " + err.Error()
			} else {
				m.BackupSchedule = s
				m.Notice = "已启用自动备份"
			}
		}
		if m.BackupSchedule.Enabled && backupButton(c, pal, "关闭", "backup-auto-off", false) {
			if m.Hooks.SetBackupSchedule != nil {
				s, err := m.Hooks.SetBackupSchedule(false, "", 0)
				if err != nil {
					m.Notice = "关闭自动备份失败: " + err.Error()
				} else {
					m.BackupSchedule = s
					m.Notice = "已关闭自动备份"
				}
			}
		}
	})
	if m.BackupSchedule.Enabled {
		mygoui.Text(c, "已启用：每 "+itoa(m.BackupSchedule.IntervalHours)+" 小时；"+m.BackupSchedule.Directory).FontSize(12).TextColor(pal.TextMuted)
	}
	mygoui.Text(c, "仅运行期间执行；最多保留 30 个，需手动清理，不自动删除。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "手动").FontSize(16).Bold()
	mygoui.Text(c, "请选择尚不存在的备份文件。运行时备份排除缓存、日志和待处理的 GeoData 更新；若配置发生变化，需重试。").FontSize(12).TextColor(pal.TextMuted)
	if backupButton(c, pal, "创建本地备份", "backup-create", m.BackupBusy) {
		if m.Hooks.BrowseBackup == nil || m.Hooks.CreateBackupAsync == nil {
			m.Notice = "本地备份不可用"
			return
		}
		path, err := m.Hooks.BrowseBackup()
		if err != nil {
			m.Notice = "选择备份位置失败: " + err.Error()
			return
		}
		if path != "" {
			m.BackupBusy = true
			m.Notice = "正在创建本地备份…"
			if err := m.Hooks.CreateBackupAsync(path, func(err error) {
				m.BackupBusy = false
				if err != nil {
					m.Notice = "备份失败: " + err.Error()
				} else {
					m.Notice = "本地备份已创建"
				}
			}); err != nil {
				m.BackupBusy = false
				m.Notice = "备份失败: " + err.Error()
			}
		}
	}
	if backupButton(c, pal, "恢复到新目录", "backup-restore", m.BackupBusy) {
		if m.Hooks.BrowseRestore == nil || m.Hooks.RestoreBackupAsync == nil {
			m.Notice = "本地恢复不可用"
			return
		}
		archive, destination, err := m.Hooks.BrowseRestore()
		if err != nil {
			m.Notice = "选择恢复位置失败: " + err.Error()
			return
		}
		if archive != "" && destination != "" {
			m.BackupBusy = true
			m.Notice = "正在验证并恢复备份…"
			if err := m.Hooks.RestoreBackupAsync(archive, destination, func(err error) {
				m.BackupBusy = false
				if err != nil {
					m.Notice = "恢复失败，新目录可能不完整: " + err.Error()
				} else {
					m.RestorePath = destination
					m.Notice = "已恢复到新目录；复制目录后可使用 NETFLOW_CONFIG_DIR 启动"
				}
			}); err != nil {
				m.BackupBusy = false
				m.Notice = "恢复失败: " + err.Error()
			}
		}
	}
	if m.RestorePath != "" && filledButton(c, pal, "复制恢复目录", "backup-copy-restore", false) {
		m.copy(m.RestorePath)
	}
	if filledButton(c, pal, "WebDAV 上传", "webdav-open", false) {
		m.Dialogs.WebDAV = true
	}
}

func (m *Model) webdavBody(c *mygoui.Context, pal Palette) {
	mygoui.Text(c, "上传会发送所选未加密备份，可能包含订阅凭据；仅支持 HTTPS。失败时远端可能留下不完整文件。").FontSize(12).TextColor(pal.Warning)
	mygoui.Row(c).Gap(6).AlignItems(mygoui.Center).Children(func() {
		mygoui.Text(c, "地址").FontSize(13)
		mygoui.TextInput(c, &m.WebDAVURLDraft).Grow(1).Label("webdav-url")
	})
	mygoui.Row(c).Gap(6).AlignItems(mygoui.Center).Children(func() {
		mygoui.Text(c, "用户").FontSize(13)
		mygoui.TextInput(c, &m.WebDAVUserDraft).Width(120).Label("webdav-user")
		mygoui.Text(c, "密码").FontSize(13)
		mygoui.TextInput(c, &m.WebDAVPasswordDraft).Password().Grow(1).Label("webdav-password")
	})
	mygoui.Text(c, "新输入的凭据只用于本次上传，不保存。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Row(c).Gap(6).Children(func() {
		if backupButton(c, pal, "选择备份并上传", "webdav-upload", m.BackupBusy) {
			m.webdavUpload(false)
		}
		if m.WebDAVSecretStored && backupButton(c, pal, "使用已保存配置上传", "webdav-upload-saved", m.BackupBusy) {
			m.webdavUpload(true)
		}
	})
	if m.WebDAVSecretStored {
		mygoui.Text(c, "检测到旧版 WebDAV 配置。Windows 会尝试使用当前账户保护；其他平台可能仍以明文保存。复制会写入剪贴板。").FontSize(12).TextColor(pal.TextMuted)
		mygoui.Row(c).Gap(4).Children(func() {
			for _, field := range []struct{ label, key string }{{"地址", "url"}, {"用户名", "user"}, {"密码", "password"}} {
				if filledButton(c, pal, "复制"+field.label, "webdav-copy-"+field.key, false) {
					if m.Hooks.CopyWebDAVField == nil {
						m.Notice = "无法读取已保存配置"
						return
					}
					if err := m.Hooks.CopyWebDAVField(field.key); err != nil {
						m.Notice = "复制失败: " + err.Error()
						return
					}
					m.Notice = "已复制" + field.label + "到剪贴板"
				}
			}
			if filledButton(c, pal, "清除密码", "webdav-clear-secret", false) {
				if m.Hooks.ClearWebDAVSecret == nil {
					m.Notice = "无法清除已保存密码"
					return
				}
				if err := m.Hooks.ClearWebDAVSecret(); err != nil {
					m.Notice = "清除密码失败: " + err.Error()
					return
				}
				m.Prefs.WebDAVPassword = ""
				m.Notice = "已清除单独保存的密码；地址中的凭据不受影响"
			}
		})
	}
}

func (m *Model) webdavUpload(useSaved bool) {
	if m.Hooks.BrowseWebDAVArchive == nil || m.Hooks.UploadWebDAVAsync == nil {
		m.Notice = "WebDAV 上传不可用"
		return
	}
	path, err := m.Hooks.BrowseWebDAVArchive()
	if err != nil {
		m.Notice = "选择备份失败: " + err.Error()
		return
	}
	if path == "" {
		return
	}
	args := agent.WebDAVUploadArgs{Archive: path, UseSaved: useSaved}
	if !useSaved {
		args.URL, args.User, args.Password = m.WebDAVURLDraft, m.WebDAVUserDraft, m.WebDAVPasswordDraft
	}
	m.WebDAVPasswordDraft = ""
	m.BackupBusy = true
	m.Notice = "正在上传未加密备份…"
	if err := m.Hooks.UploadWebDAVAsync(args, func(name string, err error) {
		m.BackupBusy = false
		if err != nil {
			m.Notice = "上传失败；远端文件可能不完整: " + name
		} else {
			m.Notice = "WebDAV 备份已上传: " + name
		}
	}); err != nil {
		m.BackupBusy = false
		m.Notice = "无法开始上传: " + err.Error()
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
	mygoui.Text(c, "协议栈").FontSize(13).Bold()
	if m.TunStack == "" {
		m.TunStack = "跟随订阅"
	}
	previous := m.TunStack
	stacks := []string{"跟随订阅", "System", "Mips"}
	if features.WithGVisor {
		stacks = []string{"跟随订阅", "System", "gVisor", "Mixed", "Mips"}
	}
	if mygoui.Select(c, &m.TunStack, stacks).Label("tun-stack").Changed() {
		values := map[string]string{"跟随订阅": "", "System": "system", "gVisor": "gvisor", "Mixed": "mixed", "Mips": "mips"}
		if m.Hooks.SetKernelOption == nil {
			m.TunStack = previous
			m.Notice = "内核设置不可用"
		} else if err := m.Hooks.SetKernelOption("tun-stack", values[m.TunStack]); err != nil {
			m.TunStack = previous
			m.Notice = err.Error()
		} else {
			m.Notice = "TUN 协议栈已保存"
		}
	}
	if !features.WithGVisor {
		mygoui.Text(c, "当前构建未包含 gVisor，Mixed 和 gVisor 不可用。").FontSize(12).TextColor(pal.Warning)
	}
	mygoui.Text(c, "跟随订阅时使用订阅指定的协议栈；未指定时使用 Mips。切换协议栈会重新加载内核。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "DNS 使用当前订阅或 DNS 覆写；虚拟网卡名称由系统管理。").FontSize(12).TextColor(pal.TextMuted)
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
	mygoui.Text(c, "填写 mihomo dns 段的 YAML 内容；保存后替换当前订阅的 DNS 段。").FontSize(12).TextColor(pal.TextMuted)
	mygoui.Text(c, "DNS 设置错误可能导致连接失败；请确认监听端口未被占用。").FontSize(12).TextColor(pal.Warning)
	mygoui.TextArea(c, &m.DNSDraft).FillWidth().Height(180).Label("dns-override-yaml")
	if filledButton(c, pal, "保存并启用", "dns-save", true) {
		p := m.currentProfile()
		if p == nil || p.UID != m.DNSProfileID || m.Hooks.SetProfileDNS == nil {
			m.Notice = "DNS 覆写不可用"
			return
		}
		if err := m.Hooks.SetProfileDNS(p.UID, true, m.DNSDraft); err != nil {
			m.Notice = err.Error()
			return
		}
		m.Dialogs.DNS = false
		m.Notice = "DNS 覆写已应用"
	}
}

func (m *Model) runtimeBody(c *mygoui.Context, pal Palette) {
	chip(c, pal, "只读", ToneMuted, false)
	mygoui.Text(c, "上次成功应用的合成配置可能包含订阅和节点凭据，请勿随意分享。外部控制接口受安全策略限制。").FontSize(12).TextColor(pal.Warning)
	mygoui.TextArea(c, &m.RuntimeConfig).FillWidth().Height(320).ReadOnly(true).Label("runtime-config")
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
					p := m.currentProfile()
					if p != nil && m.Hooks.SetProfileDNS != nil {
						if err := m.Hooks.SetProfileDNS(p.UID, true, p.Option.DNSOverride); err != nil {
							m.Notice = err.Error()
						} else {
							m.Prefs.DNSOverwrite = true
						}
					}
					m.DNSAsk = false
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
