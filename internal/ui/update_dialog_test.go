package ui

import (
	"errors"
	"strings"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/update"
)

func TestUpdateCheckIsAsyncAndShowsRelease(t *testing.T) {
	m := NewModel(HomeState{})
	var finish func(update.Result, error)
	m.Hooks.CheckUpdateAsync = func(done func(update.Result, error)) { finish = done }
	m.checkUpdate()
	if m.Busy != "check-update" || finish == nil {
		t.Fatal("missing busy state")
	}
	finish(update.Result{}, errors.New("offline"))
	if m.Busy != "" || !strings.Contains(m.Notice, "offline") {
		t.Fatal("error not shown")
	}
	m.checkUpdate()
	finish(update.Result{Current: "v1.0.0", Latest: "v2.0.0", Available: true, URL: update.ReleaseBase + "v2.0.0"}, nil)
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !m.UpdateDialog || !tt.HasText("v2.0.0") {
		t.Fatal("release dialog missing")
	}
	if _, ok := tt.Find("update-open"); !ok {
		t.Fatal("release page action missing")
	}
}
