package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestProfileOperationCanBeCanceledFromBusyView(t *testing.T) {
	m := DemoModel()
	m.OperationMessage = "正在切换订阅"
	called := 0
	m.OperationCancel = func() { called++; m.OperationCancel = nil }
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("正在切换订阅") {
		t.Fatal("busy view did not display the operation")
	}
	if err := tt.Click("取消并恢复"); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("cancel invoked %d times", called)
	}
}

func TestActivateProfileWaitsForAsyncResult(t *testing.T) {
	m := DemoModel()
	var finish func(error)
	m.Hooks.UseProfileAsync = func(uid string, done func(error)) {
		if uid != "target" {
			t.Fatalf("profile id: %q", uid)
		}
		finish = done
	}
	m.activateProfile("target")
	if finish == nil || m.Notice == "订阅已切换" {
		t.Fatal("switch reported success before the kernel finished")
	}
	finish(errors.New("synthetic failure"))
	if m.Notice != "synthetic failure" {
		t.Fatalf("failure notice: %q", m.Notice)
	}
}

func TestModeSwitchRestoresDisplayedModeOnAsyncFailure(t *testing.T) {
	m := DemoModel()
	m.Home.Mode = "rule"
	var finish func(error)
	m.Hooks.SetModeAsync = func(mode string, done func(error)) {
		if mode != "direct" {
			t.Fatalf("mode: %q", mode)
		}
		finish = done
	}
	m.setMode("direct")
	if finish == nil || m.Home.Mode != "direct" {
		t.Fatal("mode operation was not started")
	}
	finish(errors.New("synthetic failure"))
	if m.Home.Mode != "rule" || m.Notice != "synthetic failure" {
		t.Fatal("failed mode did not restore the displayed state")
	}
}

func TestKernelOptionRestoresDisplayedValueOnAsyncFailure(t *testing.T) {
	m := DemoModel()
	var finish func(error)
	m.Hooks.SetKernelOptionAsync = func(name string, value any, done func(error)) {
		if name != "ipv6" || value != true {
			t.Fatalf("option: %s %v", name, value)
		}
		finish = done
	}
	m.Prefs.IPv6 = true
	m.setKernelBool("ipv6", &m.Prefs.IPv6, true)
	if finish == nil || !m.Prefs.IPv6 {
		t.Fatal("operation did not start")
	}
	finish(errors.New("canceled"))
	if m.Prefs.IPv6 || m.Notice != "canceled" {
		t.Fatal("failure did not restore displayed value")
	}
}

func TestPortsDialogWaitsForAsyncApply(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	var finish func(error)
	m.Hooks.SetKernelPortsAsync = func(_ PortSet, done func(error)) { finish = done }
	tt := renderModel(m, WindowWidth, 1600, false)
	if err := tt.Click("ports"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("ports-save"); err != nil {
		t.Fatal(err)
	}
	if finish == nil || !m.Dialogs.Ports {
		t.Fatal("dialog closed before the operation finished")
	}
	finish(errors.New("canceled"))
	if !m.Dialogs.Ports || m.Notice != "canceled" {
		t.Fatal("failure did not keep the dialog open")
	}
	if err := tt.Click("ports-save"); err != nil {
		t.Fatal(err)
	}
	finish(nil)
	if m.Dialogs.Ports || m.Notice != "端口设置已保存" {
		t.Fatal("success did not close the dialog")
	}
}

func TestRuleApplyWaitsForValidatedAsyncTransaction(t *testing.T) {
	m := DemoModel()
	m.RuleEditor = RuleEditor{Open: true, ProposalID: "preview-1"}
	var finish func(agent.ApplyResult, error)
	discarded := ""
	m.Hooks.DiscardRewriteProposal = func(id string) { discarded = id }
	m.Hooks.ApplyRewriteAsync = func(id string, done func(agent.ApplyResult, error)) {
		if id != "preview-1" {
			t.Fatalf("proposal: %q", id)
		}
		finish = done
	}
	m.applyRulePreview()
	if finish == nil || !m.RuleEditor.Busy || !m.RuleEditor.Open {
		t.Fatal("application did not wait for the transaction")
	}
	finish(agent.ApplyResult{}, errors.New("synthetic failure"))
	if m.RuleEditor.Busy || !m.RuleEditor.Open || m.RuleEditor.ProposalID != "" || m.RuleEditor.Error != "synthetic failure" || discarded != "preview-1" {
		t.Fatal("failed application did not clear the consumed proposal")
	}
}

func TestRuleApplyAsyncReportsWarningsWithoutClosingNewEditor(t *testing.T) {
	m := DemoModel()
	m.RuleEditor = RuleEditor{Open: true, ProposalID: "preview-1"}
	var finish func(agent.ApplyResult, error)
	m.Hooks.ApplyRewriteAsync = func(_ string, done func(agent.ApplyResult, error)) { finish = done }
	m.applyRulePreview()
	m.RuleEditor = RuleEditor{Open: true, ProposalID: "preview-2"}
	finish(agent.ApplyResult{Warnings: []string{"connection already closed"}}, nil)
	if !m.RuleEditor.Open || m.RuleEditor.ProposalID != "preview-2" || !strings.Contains(m.Notice, "connection already closed") {
		t.Fatal("a stale completion closed the new editor or lost its warning")
	}
}
