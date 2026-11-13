package ui

import (
	"os"
	"path/filepath"
	"testing"

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
