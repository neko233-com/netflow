package ui

import (
	"strconv"
	"strings"

	mygoui "github.com/egoist/mygo/ui"

	"github.com/neko233-com/netflow/internal/query"
	"github.com/neko233-com/netflow/internal/rules"
)

// RuleView is the rules page.
type RuleView struct {
	Items     []rules.Item
	Providers []rules.Provider
	Query     query.Options
	Open      bool
	Loaded    bool
	ScrollTop float32
	Updating  bool
}

func (m *Model) rulesPage(c *mygoui.Context, pal Palette) {
	if !m.Rules.Loaded {
		m.Rules.Loaded = true
		if m.Hooks.RefreshRules != nil {
			m.Rules.Items, m.Rules.Providers = m.Hooks.RefreshRules()
		}
	}
	numbered := rules.Search(rules.Number(m.Rules.Items), m.Rules.Query)
	m.page(c, pal, "规则", func() {
		if len(m.Rules.Providers) == 0 {
			return
		}
		if outlinedIconButton(c, pal, iconStorage, "规则集合", "rule-providers") {
			m.Rules.Open = true
		}
	}, func() {
		mygoui.Row(c).Height(36).Padding(8, 10, 4, 10).AlignItems(mygoui.Center).Children(func() {
			searchBox(c, pal, &m.Rules.Query, "rules")
		})
		if len(numbered) == 0 {
			emptyState(c, pal)
			return
		}
		mygoui.Column(c).Children(func() {
			for _, row := range numbered {
				m.ruleRow(c, pal, row)
			}
		})
	})
	if m.Rules.ScrollTop > 100 {
		mygoui.Overlay(c, func() {
			b := mygoui.ButtonBase(c.Key("rules-top")).Absolute().Right(20).Bottom(20).Size(40, 40).Radius(20).Label("rules-top")
			bg := mygoui.RGBA(0, 0, 0, 0.1)
			if pal.Dark {
				bg = mygoui.RGBA(255, 255, 255, 0.1)
			}
			b.Background(bg)
			b.Children(func() { mygoui.Text(c, "↑").FontSize(18) })
			if b.Clicked() {
				m.Rules.ScrollTop = 0
			}
		})
	}
}

func (m *Model) ruleRow(c *mygoui.Context, pal Palette, row rules.Numbered) {
	payload := row.Item.Payload
	if payload == "" {
		payload = "-"
	}
	mygoui.Row(c).Padding(4, 16).Gap(8).AlignItems(mygoui.Center).BorderWidth(0, 0, 1, 0).BorderColor(pal.Divider).Children(func() {
		mygoui.Text(c, strconv.Itoa(row.No)).FontSize(14).TextColor(pal.TextMuted).MinWidth(30)
		mygoui.Column(c).Grow(1).Gap(2).Children(func() {
			mygoui.Text(c, payload).FontSize(16)
			mygoui.Row(c).Gap(8).Children(func() {
				mygoui.Text(c, row.Item.Type).FontSize(14).TextColor(pal.TextMuted).MinWidth(120)
				mygoui.Text(c, row.Item.Proxy).FontSize(14).TextColor(policyColor(pal, row.Item.Proxy))
			})
		})
	})
}

func policyColor(pal Palette, name string) mygoui.Color {
	switch rules.PolicyColor(name) {
	case rules.PolicyError:
		return pal.Error
	case rules.PolicyPrimary:
		return pal.Primary
	case rules.PolicySecondary:
		return pal.Secondary
	case rules.PolicyInfo:
		return pal.Info
	case rules.PolicyWarning:
		return pal.Warning
	case rules.PolicySuccess:
		return pal.Success
	default:
		return pal.Text
	}
}

func (m *Model) ruleProviderDialog(c *mygoui.Context, pal Palette) {
	if !m.Rules.Open {
		return
	}
	mygoui.Modal(c, &m.Rules.Open, func() {
		mygoui.Column(c).Width(480).MaxHeight(520).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Row(c).AlignItems(mygoui.Center).Children(func() {
				mygoui.Text(c, "规则集合").FontSize(18).Bold().Grow(1)
				if filledButton(c, pal, "更新全部", "rules-update-all", true) {
					m.updateAllRules()
				}
			})
			list := rules.SortProviders(m.Rules.Providers)
			mygoui.Column(c).MinHeight(250).Gap(8).Children(func() {
				for i := range list {
					m.ruleProviderRow(c, pal, list[i])
				}
			})
			if textButton(c, pal, "关闭", "关闭", "rules-provider-close") {
				m.Rules.Open = false
			}
		})
	})
}

func (m *Model) ruleProviderRow(c *mygoui.Context, pal Palette, p rules.Provider) {
	mygoui.Row(c).Padding(8).Radius(8).Background(pal.Node).AlignItems(mygoui.Center).Gap(8).Children(func() {
		mygoui.Column(c).Grow(1).Gap(4).Children(func() {
			mygoui.Row(c).Gap(8).AlignItems(mygoui.Center).Children(func() {
				mygoui.Text(c, p.Name).FontSize(16).SingleLine()
				mygoui.Text(c, itoa(p.Count)).FontSize(12).TextColor(pal.Primary)
			})
			if p.UpdatedAt != "" {
				mygoui.Text(c, "更新于: "+p.UpdatedAt).FontSize(12).TextColor(pal.TextMuted)
			}
			mygoui.Row(c).Gap(4).Children(func() {
				if p.Vehicle != "" {
					mygoui.Text(c, p.Vehicle).FontSize(10).Padding(0, 2).Radius(4).TextColor(pal.Secondary).Border(1, pal.Secondary.Alpha(0.5))
				}
				if p.Behavior != "" {
					mygoui.Text(c, p.Behavior).FontSize(10).Padding(0, 2).Radius(4).TextColor(pal.Secondary).Border(1, pal.Secondary.Alpha(0.5))
				}
			})
		})
		if textButton(c, pal, "更新", "更新", "rule-update-"+p.Name) {
			m.updateOneRule(p.Name)
		}
	})
}

func (m *Model) updateOneRule(name string) {
	if m.Hooks.UpdateRuleProviderAsync != nil {
		m.updateRuleProviders([]string{name})
		return
	}
	var err error
	if m.Hooks.UpdateRuleProvider != nil {
		err = m.Hooks.UpdateRuleProvider(name)
	}
	if err != nil {
		m.Notice = name + " 更新失败: " + err.Error()
		return
	}
	m.Notice = name + " 更新成功"
	m.reloadRules()
}

func (m *Model) updateAllRules() {
	names := make([]string, len(m.Rules.Providers))
	for i, p := range m.Rules.Providers {
		names[i] = p.Name
	}
	if m.Hooks.UpdateRuleProviderAsync != nil {
		m.updateRuleProviders(names)
		return
	}
	err := rules.UpdateAll(names, func(name string) error {
		if m.Hooks.UpdateRuleProvider == nil {
			return nil
		}
		return m.Hooks.UpdateRuleProvider(name)
	})
	if err != nil {
		m.Notice = err.Error()
		return
	}
	m.Notice = "所有规则集合均已更新"
	m.reloadRules()
}

func (m *Model) updateRuleProviders(names []string) {
	if m.Rules.Updating {
		return
	}
	if len(names) == 0 {
		m.Notice = "没有可更新的规则集合"
		return
	}
	m.Rules.Updating = true
	var failures []string
	completed := 0
	var next func(int)
	next = func(i int) {
		if i == len(names) {
			m.Rules.Updating = false
			m.reloadRules()
			m.Notice = "已更新 " + itoa(completed) + " 个规则集合"
			if len(failures) > 0 {
				m.Notice += "；失败：" + strings.Join(failures, "；")
			}
			return
		}
		m.Notice = "正在更新规则集合 " + itoa(i+1) + " / " + itoa(len(names))
		m.Hooks.UpdateRuleProviderAsync(names[i], func(err error) {
			if err != nil {
				failures = append(failures, names[i]+": "+err.Error())
			} else {
				completed++
			}
			next(i + 1)
		})
	}
	next(0)
}

func (m *Model) reloadRules() {
	if m.Hooks.RefreshRules == nil {
		return
	}
	m.Rules.Items, m.Rules.Providers = m.Hooks.RefreshRules()
}
