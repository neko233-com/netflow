package ui

import (
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
