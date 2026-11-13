package ui

import (
	"errors"
	"strings"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestSubscriptionAsyncWorkflowAndBulkResults(t *testing.T) {
	m := NewModel(HomeState{})
	var finish func(error)
	m.Hooks.ImportURLAsync = func(url string, done func(error)) {
		if url != "https://example.com/sub" {
			t.Fatalf("url %q", url)
		}
		finish = done
	}
	m.ProfileURL = "https://example.com/sub"
	m.importProfile(nil)
	if !m.ProfileBusy || finish == nil || !strings.Contains(m.Notice, "下载") {
		t.Fatalf("loading state: %+v", m)
	}
	m.ProfileURL = "https://example.com/next"
	finish(nil)
	if m.ProfileBusy || m.ProfileURL != "https://example.com/next" {
		t.Fatal("completion lost user input")
	}
	m.Profiles = []ProfileItem{{UID: "a", URL: "https://a.test"}, {UID: "b", URL: "https://b.test"}, {UID: "c", Type: "local"}}
	var order []string
	m.Hooks.UpdateProfileAsync = func(id string, done func(error)) { order = append(order, id); finish = done }
	m.updateAllProfiles()
	if !m.ProfileBusy || len(order) != 1 || order[0] != "a" {
		t.Fatalf("first update: %v", order)
	}
	finish(nil)
	if len(order) != 2 || order[1] != "b" {
		t.Fatalf("second update: %v", order)
	}
	finish(errors.New("network failed"))
	if m.ProfileBusy || !strings.Contains(m.Notice, "已更新 1") || !strings.Contains(m.Notice, "失败 1") {
		t.Fatalf("result: %s", m.Notice)
	}
}

func TestBulkDeleteRequiresConfirmationAndSkipsActive(t *testing.T) {
	m := NewModel(HomeState{})
	m.Router.Replace("/profile")
	m.Batch = true
	m.Profiles = []ProfileItem{{UID: "a", Name: "active", Checked: true}, {UID: "b", Name: "other", Checked: true}}
	var deleted []string
	m.Hooks.DeleteProfile = func(id string) error {
		if id == "a" {
			return errors.New("请先切换到其他订阅")
		}
		deleted = append(deleted, id)
		return nil
	}
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("batch-delete"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 || !m.BatchDeleteAsk {
		t.Fatal("deleted before confirmation")
	}
	if err := tt.Click("batch-delete-confirm"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "b" || !strings.Contains(m.Notice, "未删除 1") {
		t.Fatalf("deleted %v, notice %q", deleted, m.Notice)
	}
}
