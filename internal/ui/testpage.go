package ui

import (
	"strconv"
	"strings"

	"github.com/neko233-com/netflow/internal/sitetest"

	mygoui "github.com/egoist/mygo/ui"
)

// TestForm is the create/edit dialog for a website test.
type TestForm struct {
	Open bool
	UID  string
	Name string
	URL  string
	Icon string
}

func (m *Model) sitesBusy() bool {
	for _, s := range m.Sites {
		if s.Delay == -2 || s.Status == "testing" {
			return true
		}
	}
	return false
}

func (m *Model) testTile(c *mygoui.Context, pal Palette, i int) {
	s := m.Sites[i]
	b := mygoui.ButtonBase(c.Key("site-" + s.UID)).Height(88).Radius(8).Padding(8).Label("site-" + s.Name)
	b.Background(pal.Card).Border(1, pal.Divider).Drag(i)
	if from, ok := mygoui.Drop[int](b); ok {
		m.Sites = Move(m.Sites, from, i)
		m.saveSites()
	}
	b.Children(func() {
		mark := "网"
		if s.Icon != "" {
			r := []rune(s.Icon)
			mark = string(r[0])
		} else if s.Name != "" {
			r := []rune(s.Name)
			mark = string(r[0])
		}
		mygoui.Column(c).FillWidth().AlignItems(mygoui.Center).Gap(4).Children(func() {
			mygoui.Text(c, mark).FontSize(18).Bold()
			mygoui.Text(c, s.Name).FontSize(14).Bold().SingleLine()
			mygoui.Text(c, s.URL).FontSize(11).TextColor(pal.TextMuted).SingleLine()
			mygoui.Text(c, siteDelay(s)).FontSize(13).TextColor(siteDelayColor(pal, s.Delay))
		})
	})
	if b.Clicked() {
		m.probeOne(i)
	}
	b.ContextMenu(func(menu *mygoui.Menu) { m.siteMenu(menu, i) })
}

func (m *Model) siteMenu(menu *mygoui.Menu, i int) {
	if i < 0 || i >= len(m.Sites) {
		return
	}
	if menu.Item("编辑").Chosen() {
		s := m.Sites[i]
		m.TestForm = TestForm{Open: true, UID: s.UID, Name: s.Name, URL: s.URL, Icon: s.Icon}
	}
	if menu.Item("删除").Chosen() {
		m.Sites = append(m.Sites[:i], m.Sites[i+1:]...)
		m.saveSites()
	}
}

func siteDelay(s SiteTest) string {
	if s.Delay == -2 || s.Status == "testing" {
		return "测试中..."
	}
	if s.Delay >= 0 {
		return strconv.Itoa(s.Delay) + " ms"
	}
	return "测试"
}

func siteDelayColor(pal Palette, delay int) mygoui.Color {
	switch {
	case delay < 0:
		return pal.Primary
	case delay < 250:
		return pal.Success
	case delay < 400:
		return pal.Warning
	default:
		return pal.Error
	}
}

func (m *Model) probeOne(i int) {
	if i < 0 || i >= len(m.Sites) || m.Sites[i].Delay == -2 {
		return
	}
	m.Sites[i].Delay = -2
	m.Sites[i].Status = "testing"
	id, raw := m.Sites[i].UID, m.Sites[i].URL
	if m.Hooks.ProbeSiteAsync != nil {
		m.Hooks.ProbeSiteAsync(raw, func(ms int, err error) { m.finishProbe(id, raw, ms, err) })
		return
	}
	ms, err := 0, error(nil)
	if m.Hooks.ProbeSite != nil {
		ms, err = m.Hooks.ProbeSite(m.Sites[i].URL)
	} else if m.Hooks.TestSite != nil {
		err = m.Hooks.TestSite(m.Sites[i].URL)
		ms = 1
	}
	m.finishProbe(id, raw, ms, err)
}

func (m *Model) finishProbe(id, raw string, ms int, err error) {
	i := -1
	for j := range m.Sites {
		if m.Sites[j].UID == id && m.Sites[j].URL == raw {
			i = j
			break
		}
	}
	if i < 0 || m.Sites[i].Status != "testing" {
		return
	}
	if err != nil {
		m.Sites[i].Delay = -1
		m.Sites[i].Status = "fail"
		if sitetest.IsTimeout(err) {
			m.Notice = "检测超时或失败"
			return
		}
		m.Notice = m.Sites[i].Name + " 检测失败"
		return
	}
	if ms < 0 {
		ms = 0
	}
	m.Sites[i].Delay = ms
	m.Sites[i].Status = "ok"
}

func (m *Model) probeAll() {
	if m.sitesBusy() || len(m.Sites) == 0 {
		return
	}
	for i := range m.Sites {
		m.probeOne(i)
	}
}

func (m *Model) saveTestForm() {
	name := strings.TrimSpace(m.TestForm.Name)
	raw := strings.TrimSpace(m.TestForm.URL)
	if name == "" {
		m.Notice = "请输入名称"
		return
	}
	if raw == "" {
		m.Notice = "请输入测试链接"
		return
	}
	if m.TestForm.UID == "" {
		ids := map[string]bool{}
		for _, item := range m.Sites {
			ids[item.UID] = true
		}
		n := len(m.Sites) + 1
		for ids["t"+itoa(n)] {
			n++
		}
		m.Sites = append(m.Sites, SiteTest{
			UID: "t" + itoa(n), Name: name, URL: raw, Icon: m.TestForm.Icon, Delay: -1,
		})
	} else {
		for i := range m.Sites {
			if m.Sites[i].UID == m.TestForm.UID {
				if m.Sites[i].URL != raw {
					m.Sites[i].Delay = -1
					m.Sites[i].Status = ""
				}
				m.Sites[i].Name = name
				m.Sites[i].URL = raw
				m.Sites[i].Icon = m.TestForm.Icon
			}
		}
	}
	m.TestForm = TestForm{}
	m.saveSites()
}

func (m *Model) saveSites() {
	if m.Hooks.SaveSites == nil {
		return
	}
	if err := m.Hooks.SaveSites(m.Sites); err != nil {
		m.Notice = "保存测试项失败"
	}
}

func (m *Model) testFormDialog(c *mygoui.Context, pal Palette) {
	if !m.TestForm.Open {
		return
	}
	title := "新建测试"
	if m.TestForm.UID != "" {
		title = "编辑测试"
	}
	mygoui.Modal(c, &m.TestForm.Open, func() {
		mygoui.Column(c).Width(360).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, title).FontSize(18).Bold()
			mygoui.Text(c, "名称").FontSize(13)
			mygoui.TextInput(c, &m.TestForm.Name).Label("test-name")
			mygoui.Text(c, "测试地址").FontSize(13)
			mygoui.TextInput(c, &m.TestForm.URL).Label("test-url")
			mygoui.Text(c, "图标").FontSize(13)
			mygoui.TextInput(c, &m.TestForm.Icon).Label("test-icon")
			mygoui.Row(c).Gap(8).Justify(mygoui.End).Children(func() {
				if textButton(c, pal, "取消", "取消", "test-cancel") {
					m.TestForm = TestForm{}
				}
				if filledButton(c, pal, "保存", "test-save", true) {
					m.saveTestForm()
				}
			})
		})
	})
}
