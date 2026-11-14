package ui

import (
	"fmt"
	"strings"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/agent"
)

// VergeScriptDialog is deliberately read-only; there is no apply action.
type VergeScriptDialog struct {
	Open, Global, Profile, Busy, ConfigMode               bool
	ProfileID, PreviewID, Error, Summary, PageText, Stage string
	Page                                                  agent.PreviewRulesResult
	ConfigPage                                            agent.VergeScriptConfigPage
	Warnings                                              []string
	PreviousOffsets                                       []int
	PreviousConfigOffsets                                 []int
}

func vergeScriptWarning(s string) string {
	switch s {
	case "Read-only preview: scripts are not enabled and this preview cannot be applied.":
		return "只读预览：脚本尚未启用，此预览不能应用。"
	case "Scripts use a fixed preview time and deterministic random values; behavior can differ from Clash Verge.":
		return "脚本使用固定时间和确定性随机值，结果可能与 Clash Verge 不同。"
	case "Agent-managed rules are applied after Verge scripts. Existing connections are not rerouted.":
		return "Agent 规则在脚本后应用；已建立的连接不会重新路由。"
	case "The summary shows field names and rules only. Explicitly inspect the full configuration; it may contain credentials.":
		return "摘要只显示字段名和规则；请单独查看完整配置，其中可能包含凭据。"
	case "This preview also includes archived Verge data extensions that are currently disabled.":
		return "预览还包含当前未启用的 Verge 数据扩展。"
	case "This profile is inactive.":
		return "此订阅当前未激活。"
	case "Some external resources were not fully validated.":
		return "部分外部资源未能完整校验。"
	default:
		return s
	}
}

func (m *Model) openVergeScriptPreview(id string) {
	if id == "" || m.Hooks.PreviewVergeScriptAsync == nil || m.Hooks.VergeScriptPreviewRules == nil {
		m.Notice = "脚本预览不可用"
		return
	}
	m.clearVergeScriptPreview()
	m.VergeScriptPreview = VergeScriptDialog{Open: true, ProfileID: id, Stage: "after"}
}

func (m *Model) clearVergeScriptPreview() {
	if m.vergeScriptCancel != nil {
		m.vergeScriptCancel()
		m.vergeScriptCancel = nil
	}
	if m.VergeScriptPreview.PreviewID != "" && m.Hooks.DiscardVergeScriptPreview != nil {
		m.Hooks.DiscardVergeScriptPreview(m.VergeScriptPreview.PreviewID)
	}
	m.vergeScriptSeq++
	e := &m.VergeScriptPreview
	e.PreviewID, e.Error, e.Summary, e.PageText = "", "", "", ""
	e.Page = agent.PreviewRulesResult{}
	e.ConfigPage = agent.VergeScriptConfigPage{}
	e.Warnings, e.PreviousOffsets, e.PreviousConfigOffsets, e.Busy, e.ConfigMode = nil, nil, nil, false, false
}

func (m *Model) startVergeScriptPreview() {
	e := &m.VergeScriptPreview
	if !e.Global && !e.Profile {
		e.Error = "请至少选择一个脚本"
		return
	}
	m.clearVergeScriptPreview()
	e.Busy = true
	seq := m.vergeScriptSeq
	args := agent.VergeScriptPreviewArgs{ProfileID: e.ProfileID, Global: e.Global, Profile: e.Profile}
	cancel := m.Hooks.PreviewVergeScriptAsync(args, func(preview agent.VergeScriptPreview, err error) {
		if !m.VergeScriptPreview.Open || seq != m.vergeScriptSeq {
			if preview.PreviewID != "" && m.Hooks.DiscardVergeScriptPreview != nil {
				m.Hooks.DiscardVergeScriptPreview(preview.PreviewID)
			}
			return
		}
		m.vergeScriptCancel = nil
		e := &m.VergeScriptPreview
		e.Busy = false
		if err != nil {
			e.Error = err.Error()
			return
		}
		e.PreviewID = preview.PreviewID
		e.Summary = fmt.Sprintf("规则 %d → %d；变化字段：%s；其他字段：%d", preview.RulesBefore.Total, preview.RulesAfter.Total, strings.Join(preview.ChangedFields, ", "), preview.OtherChangedFields)
		e.Warnings = make([]string, 0, len(preview.Warnings))
		for _, warning := range preview.Warnings {
			e.Warnings = append(e.Warnings, vergeScriptWarning(warning))
		}
		e.Stage, e.Page = "after", preview.RulesAfter
		e.PageText = strings.Join(e.Page.Rules, "\n")
	})
	if seq == m.vergeScriptSeq && m.VergeScriptPreview.Open && m.VergeScriptPreview.Busy {
		m.vergeScriptCancel = cancel
	} else if cancel != nil {
		cancel()
	}
}

func (m *Model) pageVergeScriptRules(stage string, offset int) bool {
	e := &m.VergeScriptPreview
	if e.PreviewID == "" || m.Hooks.VergeScriptPreviewRules == nil {
		return false
	}
	page, err := m.Hooks.VergeScriptPreviewRules(agent.PreviewRulesArgs{ProposalID: e.PreviewID, Stage: stage, Offset: offset, Limit: 100})
	if err != nil {
		e.Error = err.Error()
		return false
	}
	if stage != e.Stage || offset == 0 {
		e.PreviousOffsets = nil
	}
	e.Error, e.Stage, e.Page = "", stage, page
	e.PageText = strings.Join(page.Rules, "\n")
	return true
}

func (m *Model) nextVergeScriptRules() {
	e := &m.VergeScriptPreview
	if e.Page.NextOffset >= e.Page.Total {
		return
	}
	offset, next := e.Page.Offset, e.Page.NextOffset
	if m.pageVergeScriptRules(e.Stage, next) {
		e.PreviousOffsets = append(e.PreviousOffsets, offset)
	}
}

func (m *Model) previousVergeScriptRules() {
	e := &m.VergeScriptPreview
	if len(e.PreviousOffsets) == 0 {
		return
	}
	last := len(e.PreviousOffsets) - 1
	offset := e.PreviousOffsets[last]
	if m.pageVergeScriptRules(e.Stage, offset) && offset != 0 {
		e.PreviousOffsets = e.PreviousOffsets[:last]
	}
}

func (m *Model) pageVergeScriptConfig(stage string, offset int) bool {
	e := &m.VergeScriptPreview
	if e.PreviewID == "" || m.Hooks.VergeScriptPreviewConfig == nil {
		return false
	}
	page, err := m.Hooks.VergeScriptPreviewConfig(agent.VergeScriptConfigArgs{PreviewID: e.PreviewID, Stage: stage, Offset: offset, Limit: 4096})
	if err != nil {
		e.Error = err.Error()
		return false
	}
	if !e.ConfigMode || stage != e.Stage || offset == 0 {
		e.PreviousConfigOffsets = nil
	}
	e.ConfigMode, e.Stage, e.ConfigPage, e.PageText, e.Error = true, stage, page, page.Text, ""
	return true
}

func (m *Model) nextVergeScriptConfig() {
	e := &m.VergeScriptPreview
	if e.ConfigPage.NextOffset >= e.ConfigPage.Total {
		return
	}
	offset, next := e.ConfigPage.Offset, e.ConfigPage.NextOffset
	if m.pageVergeScriptConfig(e.Stage, next) {
		e.PreviousConfigOffsets = append(e.PreviousConfigOffsets, offset)
	}
}
func (m *Model) previousVergeScriptConfig() {
	e := &m.VergeScriptPreview
	if len(e.PreviousConfigOffsets) == 0 {
		return
	}
	last := len(e.PreviousConfigOffsets) - 1
	offset := e.PreviousConfigOffsets[last]
	if m.pageVergeScriptConfig(e.Stage, offset) && offset != 0 {
		e.PreviousConfigOffsets = e.PreviousConfigOffsets[:last]
	}
}

func (m *Model) vergeScriptDialog(c *mygoui.Context, pal Palette) {
	e := &m.VergeScriptPreview
	if !e.Open {
		return
	}
	mygoui.Modal(c, &e.Open, func() {
		width, height := c.Size()
		width -= 112
		if width > 620 {
			width = 620
		}
		if width < 300 {
			width = 300
		}
		bodyHeight := height - 155
		if bodyHeight > 450 {
			bodyHeight = 450
		}
		if bodyHeight < 180 {
			bodyHeight = 180
		}
		mygoui.Column(c).Width(width).Padding(16).Gap(8).Radius(10).Background(pal.Dialog).Children(func() {
			mygoui.Text(c, "Verge 脚本只读预览").FontSize(18).Bold()
			mygoui.Text(c, "预览会执行所选存档脚本并离线校验；不会启用脚本或更改网络。脚本使用固定时间和确定性随机数。").FillWidth().FontSize(12).TextColor(pal.TextMuted)
			mygoui.Row(c).Gap(12).Children(func() {
				if mygoui.Checkbox(c, &e.Global, "全局脚本").Label("verge-script-global").Changed() {
					m.clearVergeScriptPreview()
				}
				if mygoui.Checkbox(c, &e.Profile, "订阅脚本").Label("verge-script-profile").Changed() {
					m.clearVergeScriptPreview()
				}
			})
			mygoui.Scroll(c).FillWidth().Height(bodyHeight).Children(func() {
				mygoui.Column(c).FillWidth().Gap(6).Children(func() {
					if e.Busy {
						mygoui.Text(c, "正在执行脚本并校验配置…").FontSize(12)
					}
					if e.Error != "" {
						mygoui.Text(c, e.Error).FontSize(12).TextColor(pal.Error)
					}
					if e.PreviewID != "" {
						mygoui.Text(c, e.Summary).FillWidth().FontSize(12).Bold()
						for _, warning := range e.Warnings {
							mygoui.Text(c, warning).FillWidth().FontSize(12).TextColor(pal.Warning)
						}
						mygoui.Row(c).Gap(8).Children(func() {
							if filledButton(c, pal, "规则", "verge-show-rules", false) {
								if m.pageVergeScriptRules("after", 0) {
									e.ConfigMode = false
									e.ConfigPage = agent.VergeScriptConfigPage{}
									e.PreviousConfigOffsets = nil
								}
							}
							if m.Hooks.VergeScriptPreviewConfig != nil && filledButton(c, pal, "查看完整配置", "verge-show-config", false) {
								m.pageVergeScriptConfig("after", 0)
							}
						})
						if e.ConfigMode {
							mygoui.Text(c, "完整配置可能包含订阅凭据，请注意周围环境。").FillWidth().FontSize(12).TextColor(pal.Warning)
						}
						mygoui.Row(c).Gap(8).Children(func() {
							if filledButton(c, pal, "变更前", "verge-before", false) {
								if e.ConfigMode {
									m.pageVergeScriptConfig("before", 0)
								} else {
									m.pageVergeScriptRules("before", 0)
								}
							}
							if filledButton(c, pal, "变更后", "verge-after", false) {
								if e.ConfigMode {
									m.pageVergeScriptConfig("after", 0)
								} else {
									m.pageVergeScriptRules("after", 0)
								}
							}
							if ((!e.ConfigMode && len(e.PreviousOffsets) > 0) || (e.ConfigMode && len(e.PreviousConfigOffsets) > 0)) && filledButton(c, pal, "上一页", "verge-prev", false) {
								if e.ConfigMode {
									m.previousVergeScriptConfig()
								} else {
									m.previousVergeScriptRules()
								}
							}
							if ((!e.ConfigMode && e.Page.NextOffset < e.Page.Total) || (e.ConfigMode && e.ConfigPage.NextOffset < e.ConfigPage.Total)) && filledButton(c, pal, "下一页", "verge-next", false) {
								if e.ConfigMode {
									m.nextVergeScriptConfig()
								} else {
									m.nextVergeScriptRules()
								}
							}
						})
						if e.ConfigMode {
							mygoui.Text(c, fmt.Sprintf("字节 %d–%d / %d", e.ConfigPage.Offset, e.ConfigPage.NextOffset, e.ConfigPage.Total)).FontSize(12)
						} else {
							start := e.Page.Offset
							if e.Page.NextOffset > start {
								start++
							}
							mygoui.Text(c, fmt.Sprintf("规则 %d–%d / %d", start, e.Page.NextOffset, e.Page.Total)).FontSize(12)
						}
						mygoui.TextArea(c, &e.PageText).FillWidth().Height(160).ReadOnly(true).Label("verge-script-rules")
					}
				})
			})
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "关闭", "verge-script-close", false) {
					e.Open = false
					m.clearVergeScriptPreview()
				}
				if filledButton(c, pal, "预览", "verge-script-preview", false) && !e.Busy {
					m.startVergeScriptPreview()
				}
			})
		})
	})
	if !e.Open {
		m.clearVergeScriptPreview()
	}
}
