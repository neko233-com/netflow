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

func TestVergeScriptConfigRevealsOnlyOnExplicitRequestAndPages(t *testing.T) {
	m := NewModel(HomeState{})
	m.VergeScriptPreview = VergeScriptDialog{Open: true, PreviewID: "id", Stage: "after"}
	requests := 0
	m.Hooks.VergeScriptPreviewConfig = func(in agent.VergeScriptConfigArgs) (agent.VergeScriptConfigPage, error) {
		requests++
		switch in.Offset {
		case 0:
			return agent.VergeScriptConfigPage{Offset: 0, NextOffset: 4, Total: 8, Text: "part"}, nil
		case 4:
			return agent.VergeScriptConfigPage{Offset: 4, NextOffset: 8, Total: 8, Text: "secret"}, nil
		default:
			t.Fatal("unexpected offset")
			return agent.VergeScriptConfigPage{}, nil
		}
	}
	if requests != 0 || m.VergeScriptPreview.ConfigMode {
		t.Fatal("configuration revealed without request")
	}
	if !m.pageVergeScriptConfig("after", 0) || m.VergeScriptPreview.PageText != "part" {
		t.Fatal("first config page missing")
	}
	m.nextVergeScriptConfig()
	if m.VergeScriptPreview.PageText != "secret" {
		t.Fatal("second config page missing")
	}
	m.previousVergeScriptConfig()
	if m.VergeScriptPreview.PageText != "part" {
		t.Fatal("previous config page missing")
	}
	m.clearVergeScriptPreview()
	if m.VergeScriptPreview.PageText != "" || m.VergeScriptPreview.ConfigPage.Text != "" {
		t.Fatal("private config retained after closing preview")
	}
}

func TestVergeScriptUIRequiresPreviewBeforeApplyAndSupportsRollback(t *testing.T) {
	m := NewModel(HomeState{})
	m.Profiles = []ProfileItem{{UID: "p", Option: ProfileOption{VergeScriptGlobal: true, VergeScriptHistory: true}}}
	var calls []string
	m.Hooks.VergeScriptPreviewRules = func(agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) { return agent.PreviewRulesResult{}, nil }
	m.Hooks.PreviewVergeScriptAsync = func(in agent.VergeScriptPreviewArgs, done func(agent.VergeScriptPreview, error)) func() {
		calls = append(calls, "preview")
		if in.Global || in.Profile {
			t.Fatal("disable preview selected scripts")
		}
		done(agent.VergeScriptPreview{PreviewID: "disable", Operation: "disable"}, nil)
		return func() {}
	}
	m.Hooks.PreviewVergeScriptRollbackAsync = func(id string, done func(agent.VergeScriptPreview, error)) func() {
		calls = append(calls, "rollback-preview")
		if id != "p" {
			t.Fatal("wrong profile")
		}
		done(agent.VergeScriptPreview{PreviewID: "rollback", Operation: "rollback"}, nil)
		return func() {}
	}
	m.Hooks.ApplyVergeScriptAsync = func(id string, done func(agent.VergeScriptApplyResult, error)) func() {
		calls = append(calls, "apply:"+id)
		done(agent.VergeScriptApplyResult{Applied: true, Active: true}, nil)
		return func() {}
	}
	m.openVergeScriptPreview("p")
	if !m.VergeScriptPreview.Enabled || !m.VergeScriptPreview.Global || !m.VergeScriptPreview.HasPrevious {
		t.Fatal("current script setting not displayed")
	}
	m.applyVergeScriptPreview()
	if len(calls) != 0 {
		t.Fatal("apply ran without preview")
	}
	m.VergeScriptPreview.Global = false
	m.startVergeScriptPreview()
	m.applyVergeScriptPreview()
	if m.VergeScriptPreview.Open || len(calls) != 2 || calls[1] != "apply:disable" {
		t.Fatal("disable preview was not applied")
	}
	m.openVergeScriptPreview("p")
	m.startVergeScriptRollbackPreview()
	m.applyVergeScriptPreview()
	if len(calls) != 4 || calls[2] != "rollback-preview" || calls[3] != "apply:rollback" {
		t.Fatal("rollback preview was not applied")
	}
}

func TestVergeScriptUICacheCleanupIsBoundedToOneRequest(t *testing.T) {
	m := NewModel(HomeState{})
	m.VergeScriptPreview = VergeScriptDialog{Open: true, PreviewID: "p"}
	var done func(agent.VergeScriptCachePruneResult, error)
	requests := 0
	m.Hooks.PruneVergeScriptCacheAsync = func(cb func(agent.VergeScriptCachePruneResult, error)) func() {
		requests++
		done = cb
		return func() {}
	}
	m.pruneVergeScriptCache()
	m.pruneVergeScriptCache()
	if requests != 1 || !m.VergeScriptPreview.Pruning {
		t.Fatal("cleanup was not serialized")
	}
	done(agent.VergeScriptCachePruneResult{Removed: 2, Bytes: 42}, nil)
	if m.VergeScriptPreview.Busy || m.VergeScriptPreview.PreviewID != "p" || m.VergeScriptPreview.CacheNotice == "" {
		t.Fatal("cleanup lost preview or result")
	}
}
