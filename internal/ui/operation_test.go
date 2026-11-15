package ui

import (
	"errors"
	"testing"
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
