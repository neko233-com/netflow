package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/rewrite"
)

func TestRuleEditorRequiresPreviewAndInvalidatesOnEdit(t *testing.T) {
	m := NewModel(HomeState{})
	m.Router.Replace("/profile")
	m.Hooks.LoadRewrite = func(scope, id string) (rewrite.Layer, error) {
		return rewrite.Layer{Prepend: []string{"DOMAIN,old.test,DIRECT"}}, nil
	}
	var change agent.Change
	applied := 0
	m.Hooks.PreviewRewrite = func(c agent.Change) (agent.Preview, error) {
		change = c
		return agent.Preview{ProposalID: "proposal", RulesBefore: []string{"MATCH,DIRECT"}, RulesAfter: []string{"DOMAIN,old.test,DIRECT", "MATCH,DIRECT"}}, nil
	}
	m.Hooks.ApplyRewrite = func(id string) (agent.ApplyResult, error) {
		if id != "proposal" {
			t.Fatalf("proposal %q", id)
		}
		applied++
		return agent.ApplyResult{}, nil
	}
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("rewrite-global"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tt.Find("rewrite-apply"); ok {
		t.Fatal("apply visible before preview")
	}
	if err := tt.Click("rewrite-preview"); err != nil {
		t.Fatal(err)
	}
	if change.Scope != "global" || len(change.Layer.Prepend) != 1 || change.Layer.Prepend[0] != "DOMAIN,old.test,DIRECT" {
		t.Fatalf("preview input %+v", change)
	}
	if _, ok := tt.Find("rewrite-apply"); !ok {
		t.Fatal("apply absent after preview")
	}
	if dir := os.Getenv("CLASHGO_SCREENSHOT_DIR"); dir != "" {
		if err := writePNG(filepath.Join(dir, "rewrite-editor.png"), tt.Image()); err != nil {
			t.Fatal(err)
		}
	}
	compact := mygoui.NewTester(m.View, WindowMinWidth, WindowMinHeight)
	button, ok := compact.Find("rewrite-apply")
	if !ok || button.Y+button.H > WindowMinHeight {
		t.Fatalf("apply button is outside compact window: %+v", button)
	}
	if err := tt.Click("rewrite-prepend"); err != nil {
		t.Fatal(err)
	}
	tt.Type("x")
	if m.RuleEditor.ProposalID != "" {
		t.Fatal("edit did not invalidate proposal")
	}
	if err := tt.Click("rewrite-preview"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("rewrite-apply"); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || m.RuleEditor.Open {
		t.Fatal("previewed rules not applied")
	}
}

func TestRuleEditorHistoryAndAsyncPreviewLifecycle(t *testing.T) {
	m := NewModel(HomeState{})
	m.Hooks.LoadRewrite = func(string, string) (rewrite.Layer, error) { return rewrite.Layer{}, nil }
	m.Hooks.RewriteHistory = func() (agent.RewriteHistory, error) {
		return agent.RewriteHistory{Entries: []rewrite.HistoryItem{{Revision: 0, RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}, nil
	}
	var pending func(agent.Preview, error)
	var rollback agent.RollbackArgs
	var discarded []string
	copied := ""
	m.Hooks.Copy = func(value string) error { copied = value; return nil }
	canceled := 0
	m.Hooks.PreviewRewriteAsync = func(_ agent.Change, done func(agent.Preview, error)) func() {
		pending = done
		return func() { canceled++ }
	}
	m.Hooks.PreviewRollbackAsync = func(in agent.RollbackArgs, done func(agent.Preview, error)) func() {
		rollback, pending = in, done
		return func() { canceled++ }
	}
	m.Hooks.DiscardRewriteProposal = func(id string) { discarded = append(discarded, id) }
	applied := ""
	m.Hooks.ApplyRewrite = func(id string) (agent.ApplyResult, error) { applied = id; return agent.ApplyResult{}, nil }
	m.openRuleEditor("profile", "chosen")
	if len(m.RuleEditor.HistoryChoices) != 1 {
		t.Fatal("history not shown")
	}
	m.previewRules()
	if !m.RuleEditor.Busy || pending == nil || m.RuleEditor.ProposalID != "" {
		t.Fatal("preview was not asynchronous")
	}
	stale := pending
	m.invalidateRulePreview()
	if canceled != 1 {
		t.Fatal("superseded validation was not canceled")
	}
	stale(agent.Preview{ProposalID: "stale"}, nil)
	if len(discarded) != 1 || discarded[0] != "stale" || m.RuleEditor.ProposalID != "" {
		t.Fatal("stale proposal was not discarded")
	}
	if dir := os.Getenv("CLASHGO_SCREENSHOT_DIR"); dir != "" {
		compact := mygoui.NewTester(m.View, WindowMinWidth, WindowMinHeight)
		if err := writePNG(filepath.Join(dir, "rewrite-history-compact.png"), compact.Image()); err != nil {
			t.Fatal(err)
		}
	}
	tt := mygoui.NewTester(m.View, WindowWidth, 1600)
	if err := tt.Click("rewrite-rollback-preview"); err != nil {
		t.Fatal(err)
	}
	if rollback.Revision == nil || *rollback.Revision != 0 || rollback.Scope != "profile" || rollback.ProfileID != "chosen" {
		t.Fatalf("wrong rollback scope: %+v", rollback)
	}
	pending(agent.Preview{ProposalID: "rollback", RulesAfter: []string{"MATCH,DIRECT"}, RulesAfterTotal: 200, RulesAfterTruncated: true, Warnings: []string{"inspect"}}, nil)
	if m.RuleEditor.Busy || m.RuleEditor.ProposalID != "rollback" || !strings.Contains(m.RuleEditor.Preview, "inspect") || !strings.Contains(m.RuleEditor.Preview, "rollback") || !strings.Contains(m.RuleEditor.Preview, "199") {
		t.Fatal("rollback result was not displayed")
	}
	if dir := os.Getenv("CLASHGO_SCREENSHOT_DIR"); dir != "" {
		compact := mygoui.NewTester(m.View, WindowMinWidth, WindowMinHeight)
		if err := writePNG(filepath.Join(dir, "rewrite-paged-compact.png"), compact.Image()); err != nil {
			t.Fatal(err)
		}
	}
	tt = mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("inspect") {
		t.Fatal("preview warning not visible")
	}
	if err := tt.Click("rewrite-copy-proposal"); err != nil || copied != "rollback" {
		t.Fatalf("proposal ID not copied: %q %v", copied, err)
	}
	if err := tt.Click("rewrite-apply"); err != nil {
		t.Fatal(err)
	}
	if applied != "rollback" || m.RuleEditor.Open {
		t.Fatal("rollback proposal not applied")
	}
	m.openRuleEditor("global", "")
	m.previewRules()
	late := pending
	m.openRuleEditor("global", "")
	if canceled != 2 {
		t.Fatal("closed dialog validation was not canceled")
	}
	late(agent.Preview{ProposalID: "old-dialog"}, nil)
	if m.RuleEditor.ProposalID != "" || discarded[len(discarded)-1] != "old-dialog" {
		t.Fatal("closed dialog accepted old preview")
	}
}
