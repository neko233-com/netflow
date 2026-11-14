package ui

import (
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestVergeScriptPreviewRequiresSelectionAndDiscardsStaleResult(t *testing.T) {
	m := NewModel(HomeState{})
	var callback func(agent.VergeScriptPreview, error)
	var canceled bool
	var discarded string
	m.Hooks.PreviewVergeScriptAsync = func(in agent.VergeScriptPreviewArgs, done func(agent.VergeScriptPreview, error)) func() {
		if in.ProfileID != "p" || !in.Global {
			t.Fatal("incorrect request")
		}
		callback = done
		return func() { canceled = true }
	}
	m.Hooks.VergeScriptPreviewRules = func(agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) { return agent.PreviewRulesResult{}, nil }
	m.Hooks.DiscardVergeScriptPreview = func(id string) { discarded = id }
	m.openVergeScriptPreview("p")
	m.startVergeScriptPreview()
	if m.VergeScriptPreview.Error == "" || callback != nil {
		t.Fatal("empty selection accepted")
	}
	m.VergeScriptPreview.Global = true
	m.startVergeScriptPreview()
	if !m.VergeScriptPreview.Busy || callback == nil {
		t.Fatal("preview did not start")
	}
	m.clearVergeScriptPreview()
	callback(agent.VergeScriptPreview{PreviewID: "stale"}, nil)
	if !canceled || discarded != "stale" || m.VergeScriptPreview.PreviewID != "" {
		t.Fatal("stale preview was retained")
	}
}

func TestVergeScriptPreviewDisplaysAndPagesRules(t *testing.T) {
	m := NewModel(HomeState{})
	m.Hooks.PreviewVergeScriptAsync = func(_ agent.VergeScriptPreviewArgs, done func(agent.VergeScriptPreview, error)) func() {
		done(agent.VergeScriptPreview{PreviewID: "id", ChangedFields: []string{"rules"}, RulesBefore: agent.PreviewRulesResult{Total: 1}, RulesAfter: agent.PreviewRulesResult{Total: 2, NextOffset: 1, Rules: []string{"DOMAIN,a,DIRECT"}}}, nil)
		return func() {}
	}
	m.Hooks.VergeScriptPreviewRules = func(in agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) {
		if in.ProposalID != "id" || in.Stage != "after" || in.Offset != 1 {
			t.Fatal("invalid page request")
		}
		return agent.PreviewRulesResult{Offset: 1, NextOffset: 2, Total: 2, Rules: []string{"MATCH,DIRECT"}}, nil
	}
	m.openVergeScriptPreview("p")
	m.VergeScriptPreview.Profile = true
	m.startVergeScriptPreview()
	if m.VergeScriptPreview.PreviewID != "id" || m.VergeScriptPreview.PageText != "DOMAIN,a,DIRECT" {
		t.Fatal("preview not displayed")
	}
	if !m.pageVergeScriptRules("after", 1) || m.VergeScriptPreview.PageText != "MATCH,DIRECT" {
		t.Fatal("page not displayed")
	}
}

func TestVergeScriptPreviewBackTracksShortPages(t *testing.T) {
	m := NewModel(HomeState{})
	m.VergeScriptPreview = VergeScriptDialog{Open: true, PreviewID: "id", Stage: "after", Page: agent.PreviewRulesResult{Offset: 0, NextOffset: 2, Total: 5}}
	m.Hooks.VergeScriptPreviewRules = func(in agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) {
		next := in.Offset + 2
		if next > 5 {
			next = 5
		}
		return agent.PreviewRulesResult{Offset: in.Offset, NextOffset: next, Total: 5}, nil
	}
	m.nextVergeScriptRules()
	m.nextVergeScriptRules()
	if m.VergeScriptPreview.Page.Offset != 4 {
		t.Fatal("did not advance through short pages")
	}
	m.previousVergeScriptRules()
	if m.VergeScriptPreview.Page.Offset != 2 {
		t.Fatal("did not return to previous short page")
	}
	m.previousVergeScriptRules()
	if m.VergeScriptPreview.Page.Offset != 0 || len(m.VergeScriptPreview.PreviousOffsets) != 0 {
		t.Fatal("did not return to first page")
	}
}
