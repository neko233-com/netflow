package ui

import (
	"fmt"
	"strings"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type RuleEditor struct {
	Open                       bool
	Scope, ProfileID           string
	Prepend, Append, Remove    string
	ProposalID, Preview, Error string
	History                    []rewrite.HistoryItem
	HistoryChoices             []string
	HistorySelected            string
	Busy                       bool
}

func (m *Model) openRuleEditor(scope, profileID string) {
	if m.Hooks.LoadRewrite == nil || (m.Hooks.PreviewRewrite == nil && m.Hooks.PreviewRewriteAsync == nil) || m.Hooks.ApplyRewrite == nil {
		m.Notice = "规则覆写接口不可用"
		return
	}
	layer, err := m.Hooks.LoadRewrite(scope, profileID)
	if err != nil {
		m.Notice = err.Error()
		return
	}
	m.invalidateRulePreview()
	m.RuleEditor = RuleEditor{Open: true, Scope: scope, ProfileID: profileID, Prepend: strings.Join(layer.Prepend, "\n"), Append: strings.Join(layer.Append, "\n"), Remove: strings.Join(layer.Remove, "\n")}
	if m.Hooks.RewriteHistory != nil {
		history, err := m.Hooks.RewriteHistory()
		if err != nil {
			m.RuleEditor.Error = err.Error()
			return
		}
		m.RuleEditor.History = history.Entries
		for _, item := range history.Entries {
			m.RuleEditor.HistoryChoices = append(m.RuleEditor.HistoryChoices, fmt.Sprintf("版本 %d · %s", item.Revision, item.RecordedAt.Local().Format("2006-01-02 15:04:05")))
		}
		if len(m.RuleEditor.HistoryChoices) > 0 {
			m.RuleEditor.HistorySelected = m.RuleEditor.HistoryChoices[0]
		}
	}
}

func ruleLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (m *Model) previewRules() {
	e := &m.RuleEditor
	change := agent.Change{Scope: e.Scope, Operation: "set", ProfileID: e.ProfileID, Layer: rewrite.Layer{Prepend: ruleLines(e.Prepend), Append: ruleLines(e.Append), Remove: ruleLines(e.Remove)}}
	m.startRulePreview(func(done func(agent.Preview, error)) func() {
		if m.Hooks.PreviewRewriteAsync != nil {
			return m.Hooks.PreviewRewriteAsync(change, done)
		}
		preview, err := m.Hooks.PreviewRewrite(change)
		done(preview, err)
		return func() {}
	})
}

func (m *Model) invalidateRulePreview() {
	if m.ruleEditorCancel != nil {
		m.ruleEditorCancel()
		m.ruleEditorCancel = nil
	}
	if m.RuleEditor.ProposalID != "" && m.Hooks.DiscardRewriteProposal != nil {
		m.Hooks.DiscardRewriteProposal(m.RuleEditor.ProposalID)
	}
	m.ruleEditorSeq++
	m.RuleEditor.ProposalID, m.RuleEditor.Preview, m.RuleEditor.Error = "", "", ""
	m.RuleEditor.Busy = false
}

func (m *Model) previewRuleRollback() {
	e := &m.RuleEditor
	if m.Hooks.PreviewRollbackAsync == nil {
		e.Error = "历史回滚不可用"
		return
	}
	for i, choice := range e.HistoryChoices {
		if choice != e.HistorySelected {
			continue
		}
		revision := e.History[i].Revision
		args := agent.RollbackArgs{Revision: &revision, Scope: e.Scope, ProfileID: e.ProfileID}
		m.startRulePreview(func(done func(agent.Preview, error)) func() { return m.Hooks.PreviewRollbackAsync(args, done) })
		return
	}
	e.Error = "请选择历史版本"
}

func (m *Model) startRulePreview(start func(func(agent.Preview, error)) func()) {
	m.invalidateRulePreview()
	m.RuleEditor.Busy = true
	seq := m.ruleEditorSeq
	cancel := start(func(preview agent.Preview, err error) {
		if !m.RuleEditor.Open || seq != m.ruleEditorSeq {
			if preview.ProposalID != "" && m.Hooks.DiscardRewriteProposal != nil {
				m.Hooks.DiscardRewriteProposal(preview.ProposalID)
			}
			return
		}
		m.ruleEditorCancel = nil
		m.RuleEditor.Busy = false
		m.finishRulePreview(preview, err)
	})
	if seq == m.ruleEditorSeq && m.RuleEditor.Open && m.RuleEditor.Busy {
		m.ruleEditorCancel = cancel
	} else if cancel != nil {
		cancel()
	}
}

func (m *Model) finishRulePreview(preview agent.Preview, err error) {
	e := &m.RuleEditor
	if err != nil {
		e.Error = err.Error()
		e.ProposalID = ""
		return
	}
	e.Error = ""
	e.ProposalID = preview.ProposalID
	lines := []string{fmt.Sprintf("规则数量：%d → %d", len(preview.RulesBefore), len(preview.RulesAfter))}
	lines = append(lines, preview.Warnings...)
	lines = append(lines, "应用后的规则：")
	limit := len(preview.RulesAfter)
	if limit > 100 {
		limit = 100
	}
	lines = append(lines, preview.RulesAfter[:limit]...)
	if limit < len(preview.RulesAfter) {
		lines = append(lines, fmt.Sprintf("… 另有 %d 条规则", len(preview.RulesAfter)-limit))
	}
	e.Preview = strings.Join(lines, "\n")
}

func (m *Model) ruleEditorDialog(c *mygoui.Context, pal Palette) {
	e := &m.RuleEditor
	if !e.Open {
		return
	}
	mygoui.Modal(c, &e.Open, func() {
		width, height := c.Size()
		// Modal and column padding both contribute to the outer width.
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
		mygoui.Column(c).Width(width).Padding(16).Gap(6).Radius(10).Background(pal.Dialog).Children(func() {
			title := "全局规则覆写"
			if e.Scope == "profile" {
				title = "订阅规则覆写"
			}
			mygoui.Text(c, title).FontSize(18).Bold()
			mygoui.Text(c, "每行一条 mihomo 规则；移除项需要与订阅原规则完全一致。").FontSize(12).TextColor(pal.TextMuted)
			mygoui.Scroll(c).FillWidth().Height(bodyHeight).Children(func() {
				mygoui.Column(c).FillWidth().Gap(6).Children(func() {
					if len(e.HistoryChoices) > 0 && m.Hooks.PreviewRollbackAsync != nil {
						mygoui.Text(c, "历史版本（只恢复当前范围）").FontSize(12).Bold()
						mygoui.Row(c).FillWidth().Gap(8).Children(func() {
							if mygoui.Select(c, &e.HistorySelected, e.HistoryChoices).Grow(1).Label("rewrite-history").Changed() {
								m.invalidateRulePreview()
							}
							if filledButton(c, pal, "预览回滚", "rewrite-rollback-preview", false) && !e.Busy {
								m.previewRuleRollback()
							}
						})
					}
					if e.Busy {
						mygoui.Text(c, "正在校验规则…").FontSize(12).TextColor(pal.TextMuted)
					}
					if e.Error != "" {
						mygoui.Text(c, e.Error).FontSize(12).TextColor(pal.Error)
					}
					if e.Preview != "" {
						mygoui.TextArea(c, &e.Preview).FillWidth().Height(105).ReadOnly(true).Label("rewrite-preview-result")
					}
					for _, field := range []struct {
						label, id string
						value     *string
					}{{"前置规则", "rewrite-prepend", &e.Prepend}, {"追加规则（位于 MATCH 前）", "rewrite-append", &e.Append}, {"移除订阅原规则", "rewrite-remove", &e.Remove}} {
						mygoui.Text(c, field.label).FontSize(12).Bold()
						if mygoui.TextArea(c, field.value).FillWidth().Height(54).Label(field.id).Changed() {
							m.invalidateRulePreview()
						}
					}
				})
			})
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "取消", "rewrite-cancel", false) {
					e.Open = false
					m.invalidateRulePreview()
				}
				if filledButton(c, pal, "预览", "rewrite-preview", false) && !e.Busy {
					m.previewRules()
				}
				if e.ProposalID != "" && filledButton(c, pal, "应用规则", "rewrite-apply", true) {
					result, err := m.Hooks.ApplyRewrite(e.ProposalID)
					if err != nil {
						e.Error = err.Error()
						e.ProposalID = ""
					} else {
						e.Open = false
						m.Notice = "规则覆写已应用"
						if len(result.Warnings) > 0 {
							m.Notice += "；" + strings.Join(result.Warnings, "；")
						}
					}
				}
			})
		})
	})
	if !e.Open {
		m.invalidateRulePreview()
	}
}
