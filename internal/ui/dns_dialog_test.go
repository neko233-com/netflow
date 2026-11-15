package ui

import (
	"errors"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestDNSDialogDoesNotApplyToDifferentProfile(t *testing.T) {
	m := NewModel(HomeState{})
	m.Router.Replace("/settings")
	m.Profiles = []ProfileItem{{UID: "one"}, {UID: "two"}}
	m.CurrentProfile = "two"
	m.DNSProfileID = "one"
	m.DNSDraft = "enable: false"
	m.Dialogs.DNS = true
	calls := 0
	m.Hooks.SetProfileDNS = func(string, bool, string) error { calls++; return nil }
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("dns-save"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || m.Notice == "" {
		t.Fatal("DNS draft applied to a different profile")
	}
}

func TestDNSDialogWaitsForAsyncApply(t *testing.T) {
	m := NewModel(HomeState{})
	m.Router.Replace("/settings")
	m.Profiles = []ProfileItem{{UID: "one"}}
	m.CurrentProfile = "one"
	m.DNSProfileID = "one"
	m.DNSDraft = "enable: false"
	m.Dialogs.DNS = true
	var finish func(error)
	m.Hooks.SetProfileDNSAsync = func(id string, enabled bool, text string, done func(error)) {
		if id != "one" || !enabled || text != "enable: false" {
			t.Fatal("incorrect DNS request")
		}
		finish = done
	}
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("dns-save"); err != nil {
		t.Fatal(err)
	}
	if finish == nil || !m.Dialogs.DNS {
		t.Fatal("dialog closed early")
	}
	finish(errors.New("canceled"))
	if !m.Dialogs.DNS || m.Notice != "canceled" {
		t.Fatal("failure lost")
	}
	if err := tt.Click("dns-save"); err != nil {
		t.Fatal(err)
	}
	finish(nil)
	if m.Dialogs.DNS || m.Notice != "DNS 覆写已应用" {
		t.Fatal("success not reflected")
	}
}
