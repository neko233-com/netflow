package ui

import (
	"strings"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

func (m *Model) profilePage(c *mygoui.Context, pal Palette) {
	m.page(c, pal, "订阅", func() {
		if m.Batch {
			m.batchTools(c, pal)
			return
		}
		if textButton(c, pal, "批量", "批量操作", "batch") {
			m.Batch = true
		}
		if textButton(c, pal, "更新", "更新所有订阅", "update-all") {
			m.updateAllProfiles()
		}
		if textButton(c, pal, "配置", "查看运行时订阅", "runtime") {
			m.openRuntimeConfig()
		}
		if textButton(c, pal, "激活", "重新激活订阅", "reactivate") {
			if m.CurrentProfile == "" {
				m.Notice = "没有已激活的订阅"
			} else {
				m.activateProfile(m.CurrentProfile)
			}
		}
	}, func() {
		zone := mygoui.Column(c).FillWidth().Padding(10).Gap(12)
		zone.Children(func() {
			m.importRow(c, pal)
			w, _ := c.Size()
			cols := ProfileColumns(contentWidth(w, m.sidebarWidth()))
			mygoui.Grid(c).Columns(cols).Gap(8).Children(func() {
				for i := range m.Profiles {
					m.profileItem(c, pal, i)
				}
			})
			mygoui.Box(c).FillWidth().Height(1).Label("profile-rule").Background(pal.Divider)
			mygoui.Grid(c).Columns(2).Gap(8).Children(func() {
				m.rewriteCard(c, pal, "全局规则覆写", "所有订阅共享", "global", "")
				m.rewriteCard(c, pal, "当前订阅规则覆写", "只影响当前订阅", "profile", m.CurrentProfile)
			})
		})
		if files := zone.DroppedFiles(); len(files) > 0 {
			m.dropProfiles(files)
		}
	})
}

func (m *Model) importRow(c *mygoui.Context, pal Palette) {
	mygoui.Row(c).Height(36).Gap(8).AlignItems(mygoui.Center).Children(func() {
		field := mygoui.TextInput(c, &m.ProfileURL).Placeholder("订阅文件链接").Grow(1).Disabled(m.ProfileBusy).Label("profile-url")
		if field.Submitted() {
			m.importProfile(c)
		}
		if strings.TrimSpace(m.ProfileURL) == "" {
			if textButton(c, pal, "粘贴", "粘贴", "paste-url") {
				m.ProfileURL = c.ReadClipboard()
			}
		} else if textButton(c, pal, "清除", "清除", "clear-url") {
			m.ProfileURL = ""
		}
		disabled := strings.TrimSpace(m.ProfileURL) == "" || m.ProfileBusy
		b := mygoui.ButtonBase(c.Key("do-import")).Height(28).Padding(0, 10).Radius(6).Label("do-import")
		if disabled {
			b.Background(pal.TextMuted.Alpha(0.18)).TextColor(pal.TextMuted)
		} else {
			b.Background(pal.Primary).TextColor(pal.OnPrimary)
		}
		b.Disabled(disabled)
		b.Children(func() { mygoui.Text(c, "导入").FontSize(13) })
		if b.Clicked() {
			m.importProfile(c)
		}
		if filledButton(c, pal, "本地文件", "profile-local", false) && !m.ProfileBusy {
			if m.Hooks.BrowseProfiles != nil {
				files, err := m.Hooks.BrowseProfiles()
				if err != nil {
					m.Notice = err.Error()
				} else {
					m.dropProfiles(files)
				}
			}
		}
		if filledButton(c, pal, "新建", "profile-new", false) && !m.ProfileBusy {
			m.Form = ProfileForm{Open: true, Type: "remote", Timeout: 60, Interval: 1440, Auto: true}
		}
	})
}

func (m *Model) importProfile(c *mygoui.Context) {
	if m.ProfileBusy {
		return
	}
	raw := strings.TrimSpace(m.ProfileURL)
	if !ValidSubscriptionURL(raw) {
		m.Notice = "无效的订阅链接，请输入以 http:// 或 https:// 开头的地址"
		return
	}
	if m.Hooks.ImportURLAsync != nil {
		m.ProfileBusy = true
		m.Notice = "正在下载订阅…"
		m.Hooks.ImportURLAsync(raw, func(err error) {
			m.ProfileBusy = false
			if err != nil {
				m.Notice = err.Error()
				return
			}
			if m.ProfileURL == raw {
				m.ProfileURL = ""
			}
			m.Notice = "订阅已导入"
		})
		return
	}
	if m.Hooks.ImportURL != nil {
		if err := m.Hooks.ImportURL(raw); err != nil {
			m.Notice = err.Error()
			return
		}
		m.ProfileURL = ""
		m.Notice = "订阅已成功导入，如未显示请重启应用"
		return
	}
	m.addProfile(ProfileItem{
		UID:     "u" + itoa(len(m.Profiles)+1),
		Name:    URLHost(raw),
		URL:     raw,
		Type:    "remote",
		Updated: time.Now(),
		Option:  ProfileOption{UpdateInterval: 1440, AllowAutoUpdate: true, TimeoutSeconds: 60},
	})
	m.ProfileURL = ""
	m.Notice = "订阅已成功导入，如未显示请重启应用"
	_ = c
}

func (m *Model) addProfile(item ProfileItem) {
	if item.UID == "" {
		item.UID = "u" + itoa(len(m.Profiles)+1)
	}
	m.Profiles = append(m.Profiles, item)
	if m.CurrentProfile == "" {
		m.CurrentProfile = item.UID
		m.Home.Profile = homeFrom(item)
	}
}

func homeFrom(item ProfileItem) *HomeProfile {
	return &HomeProfile{
		Name: item.Name, URL: item.URL, Home: item.Home, Updated: item.Updated,
		Used: item.Used, Total: item.Total, Expire: item.Expire,
	}
}

func (m *Model) dropProfiles(files []string) {
	for _, f := range files {
		low := strings.ToLower(f)
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			m.Notice = "仅支持 YAML 文件"
			continue
		}
		if m.Hooks.ImportLocal != nil {
			if err := m.Hooks.ImportLocal(f); err != nil {
				m.Notice = err.Error()
			} else {
				m.Notice = "本地配置已导入"
			}
			continue
		}
		name := f
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			name = name[i+1:]
		}
		m.addProfile(ProfileItem{Name: name, Type: "local", Updated: time.Now()})
	}
}

func (m *Model) batchTools(c *mygoui.Context, pal Palette) {
	n := 0
	for _, p := range m.Profiles {
		if p.Checked {
			n++
		}
	}
	all := n == len(m.Profiles) && n > 0
	label := "全选"
	if all {
		label = "取消全选"
	} else if n > 0 {
		label = "半选"
	}
	if textButton(c, pal, label, label, "batch-all") {
		for i := range m.Profiles {
			m.Profiles[i].Checked = !all
		}
	}
	del := mygoui.ButtonBase(c.Key("batch-delete")).Height(28).Padding(0, 8).Disabled(n == 0).Label("batch-delete")
	del.Children(func() { mygoui.Text(c, "删除").FontSize(13).TextColor(pal.Error) })
	if del.Clicked() {
		m.BatchDeleteAsk = true
	}
	if filledButton(c, pal, "完成", "batch-done", false) {
		m.Batch = false
		for i := range m.Profiles {
			m.Profiles[i].Checked = false
		}
	}
	mygoui.Text(c, "已选中 "+itoa(n)+" 项目").FontSize(13).TextColor(pal.TextMuted)
}

func (m *Model) deleteChecked() {
	if m.Hooks.DeleteProfile != nil {
		var ids []string
		for _, p := range m.Profiles {
			if p.Checked {
				ids = append(ids, p.UID)
			}
		}
		deleted := 0
		var failures []string
		for _, id := range ids {
			if err := m.Hooks.DeleteProfile(id); err != nil {
				failures = append(failures, err.Error())
			} else {
				deleted++
			}
		}
		m.Batch = false
		m.Notice = "已删除 " + itoa(deleted) + " 个订阅"
		if len(failures) > 0 {
			m.Notice += "；未删除 " + itoa(len(failures)) + " 个：" + strings.Join(failures, "；")
		}
		return
	}
	var keep []ProfileItem
	for _, p := range m.Profiles {
		if !p.Checked {
			keep = append(keep, p)
		} else if p.UID == m.CurrentProfile {
			m.CurrentProfile = ""
			m.Home.Profile = nil
		}
	}
	m.Profiles = keep
	m.Notice = "选中的订阅已成功删除"
	m.Batch = false
}

func (m *Model) profileItem(c *mygoui.Context, pal Palette, i int) {
	p := &m.Profiles[i]
	selected := p.UID == m.CurrentProfile
	card := mygoui.ButtonBase(c.Key("profile-"+p.UID)).FillWidth().Padding(8, 16).Radius(8).Label("profile-" + p.Name)
	card.Background(pal.Card)
	if selected {
		card.BorderWidth(0, 0, 0, 3).BorderColor(pal.Primary)
	}
	card.Drag(i)
	if from, ok := mygoui.Drop[int](card); ok {
		m.Profiles = Move(m.Profiles, from, i)
	}
	card.ContextMenu(func(menu *mygoui.Menu) {
		m.profileMenu(c, menu, p)
	})
	card.Children(func() {
		mygoui.Column(c).FillWidth().AlignItems(mygoui.Stretch).Gap(6).Children(func() {
			mygoui.Row(c).AlignItems(mygoui.Center).Gap(6).Children(func() {
				if m.Batch {
					on := p.Checked
					sw := mygoui.Checkbox(c, &on, "").Label("check-" + p.UID)
					if sw.Changed() {
						p.Checked = on
					}
				}
				mygoui.Text(c, "⋮⋮").FontSize(12).TextColor(pal.TextMuted)
				title := mygoui.Text(c, p.Name).FontSize(18).FontWeight(600).SingleLine().Grow(1)
				if selected {
					title.TextColor(pal.Primary)
				}
				if p.URL != "" {
					if textButton(c, pal, "刷新", "更新", "refresh-"+p.UID) {
						m.updateProfile(p.UID)
					}
				}
			})
			desc := p.Description
			if desc == "" && p.URL != "" {
				desc = URLHost(p.URL)
			}
			mygoui.Text(c, desc).FontSize(14).TextColor(pal.TextMuted)
			if p.Total > 0 {
				mygoui.Row(c).FillWidth().Children(func() {
					mygoui.Text(c, FormatTraffic(p.Used)+"/"+FormatTraffic(p.Total)).FontSize(14).Grow(1)
					if !p.Expire.IsZero() {
						mygoui.Text(c, p.Expire.Format("2006-01-02")).FontSize(14)
					}
				})
				meter(c, pal, UsagePercent(p.Used, p.Total))
			} else if !p.Updated.IsZero() {
				mygoui.Text(c, p.Updated.Format("2006-01-02 15:04")).FontSize(12).TextColor(pal.TextMuted)
			}
		})
	})
	if card.Clicked() && !m.Batch {
		m.activateProfile(p.UID)
	}
}

// activateProfile switches the current subscription. When the app hook is
// set, that path reloads the kernel and restores this profile's selected
// nodes. A nil hook only updates the model, which is what headless pages do.
func (m *Model) activateProfile(uid string) {
	if uid == "" {
		return
	}
	if m.Hooks.UseProfile != nil {
		if err := m.Hooks.UseProfile(uid); err != nil {
			m.Notice = err.Error()
			return
		}
		m.Notice = "订阅已切换"
		return
	}
	for _, p := range m.Profiles {
		if p.UID != uid {
			continue
		}
		m.CurrentProfile = uid
		m.Home.Profile = homeFrom(p)
		m.Notice = "订阅已切换"
		return
	}
}

func (m *Model) profileMenu(c *mygoui.Context, menu *mygoui.Menu, p *ProfileItem) {
	remote := p.URL != ""
	if remote && p.Home != "" {
		if menu.Item("首 页").Chosen() {
			m.openProfileHome(c, p.Home)
		}
	}
	if menu.Item("使用").Chosen() {
		m.activateProfile(p.UID)
	}
	if remote {
		if menu.Item("分享二维码").Chosen() {
			m.openProfileQR(p.URL)
		}
		if menu.Item("更换订阅链接").Chosen() {
			if m.ProfileBusy || m.Hooks.ChangeProfileURLAsync == nil {
				m.Notice = "订阅操作暂不可用"
			} else {
				m.ProfileURLChangeUID, m.ProfileURLChange, m.ProfileURLChangeErr = p.UID, p.URL, ""
			}
		}
	}
	if menu.Item("编辑信息").Chosen() {
		m.Form = ProfileForm{
			Open: true, Editing: true, UID: p.UID, Type: p.Type, Name: p.Name, Desc: p.Description,
			URL: p.URL, UA: p.Option.UserAgent, Timeout: p.Option.TimeoutSeconds, Interval: p.Option.UpdateInterval,
			SysProxy: p.Option.UseSystemProxy, Clash: p.Option.UseClashProxy, Insecure: p.Option.AcceptInvalid,
			Auto: p.Option.AllowAutoUpdate,
		}
		if m.Form.Timeout <= 0 {
			m.Form.Timeout = 20
		}
		if m.Form.Type == "" {
			m.Form.Type = "local"
		}
	}
	if menu.Item("编辑文件").Chosen() {
		m.openProfileFile(p.UID)
	}
	if menu.Item("编辑规则覆写").Chosen() {
		m.openRuleEditor("profile", p.UID)
	}
	preview := menu.Item("预览 Verge 脚本")
	if !p.Option.HasVergeArchive {
		preview.Disabled(true)
	}
	if preview.Chosen() {
		m.openVergeScriptPreview(p.UID)
	}
	proxies := menu.Item("编辑节点")
	if p.Option.Proxies == "" {
		proxies.Disabled(true)
	}
	groups := menu.Item("编辑代理组")
	if p.Option.Groups == "" {
		groups.Disabled(true)
	}
	merge := menu.Item("扩展覆写配置")
	if p.Option.Merge == "" {
		merge.Disabled(true)
	}
	script := menu.Item("扩展脚本")
	if p.Option.Script == "" {
		script.Disabled(true)
	}
	if menu.Item("打开文件").Chosen() {
		m.openProfileFile(p.UID)
	}
	if remote {
		if menu.Item("更新").Chosen() {
			m.updateProfile(p.UID)
		}
		if menu.Item("更新（代理）").Chosen() {
			m.updateProfileViaProxy(p.UID)
		}
	}
	if menu.Item("删除").Chosen() {
		if m.Batch {
			p.Checked = !p.Checked
			return
		}
		m.DeleteUID = p.UID
	}
	_ = proxies
	_ = groups
	_ = merge
	_ = script
}

func (m *Model) updateProfileViaProxy(uid string) {
	if m.ProfileBusy {
		return
	}
	if m.Hooks.UpdateProfileViaProxyAsync == nil {
		m.Notice = "通过内核代理更新订阅不可用"
		return
	}
	m.ProfileBusy = true
	m.Notice = "正在通过内核代理更新订阅…"
	m.Hooks.UpdateProfileViaProxyAsync(uid, func(err error) {
		m.ProfileBusy = false
		if err != nil {
			m.Notice = err.Error()
		} else {
			m.Notice = "订阅已通过内核代理更新"
		}
	})
}

func (m *Model) updateProfile(uid string) {
	if m.ProfileBusy {
		return
	}
	if m.Hooks.UpdateProfileAsync != nil {
		m.ProfileBusy = true
		m.Notice = "正在更新订阅…"
		m.Hooks.UpdateProfileAsync(uid, func(err error) {
			m.ProfileBusy = false
			if err != nil {
				m.Notice = err.Error()
			} else {
				m.Notice = "订阅已更新"
			}
		})
		return
	}
	if m.Hooks.UpdateProfile == nil {
		m.Notice = "更新订阅尚未实现"
		return
	}
	if err := m.Hooks.UpdateProfile(uid); err != nil {
		m.Notice = err.Error()
		return
	}
	m.Notice = "订阅已更新"
}

func (m *Model) updateAllProfiles() {
	if m.ProfileBusy {
		return
	}
	var ids []string
	for _, p := range m.Profiles {
		if p.URL != "" {
			ids = append(ids, p.UID)
		}
	}
	if len(ids) == 0 {
		m.Notice = "没有可更新的远程订阅"
		return
	}
	if m.Hooks.UpdateProfileAsync == nil && m.Hooks.UpdateProfile == nil {
		m.Notice = "订阅更新不可用"
		return
	}
	m.ProfileBusy = true
	var failures []string
	completed := 0
	var next func(int)
	next = func(i int) {
		if i == len(ids) {
			m.ProfileBusy = false
			m.Notice = "已更新 " + itoa(completed) + " 个订阅"
			if len(failures) > 0 {
				m.Notice += "；失败 " + itoa(len(failures)) + " 个：" + strings.Join(failures, "；")
			}
			return
		}
		m.Notice = "正在更新订阅 " + itoa(i+1) + " / " + itoa(len(ids))
		done := func(err error) {
			if err != nil {
				failures = append(failures, err.Error())
			} else {
				completed++
			}
			next(i + 1)
		}
		if m.Hooks.UpdateProfileAsync != nil {
			m.Hooks.UpdateProfileAsync(ids[i], done)
		} else {
			done(m.Hooks.UpdateProfile(ids[i]))
		}
	}
	next(0)
}

func (m *Model) rewriteCard(c *mygoui.Context, pal Palette, title, desc, scope, profileID string) {
	b := mygoui.ButtonBase(c.Key("rewrite-" + scope)).FillWidth().Padding(14).Radius(8).Background(pal.Card).Label("rewrite-" + scope)
	b.Children(func() {
		mygoui.Column(c).FillWidth().AlignItems(mygoui.Stretch).Gap(6).Children(func() {
			mygoui.Row(c).AlignItems(mygoui.Center).Children(func() {
				mygoui.Text(c, title).FontSize(14).Grow(1)
				chip(c, pal, "编辑", TonePrimary, false)
			})
			mygoui.Text(c, desc+" · 先预览再应用").FontSize(12).TextColor(pal.TextMuted)
		})
	})
	if b.Clicked() {
		m.openRuleEditor(scope, profileID)
	}
}

func (m *Model) deleteTarget() *ProfileItem {
	for i := range m.Profiles {
		if m.Profiles[i].UID == m.DeleteUID {
			return &m.Profiles[i]
		}
	}
	return nil
}
