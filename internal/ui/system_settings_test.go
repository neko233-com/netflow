package ui

import (
	"errors"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestSystemSettingsRestoreSwitchAfterFailure(t *testing.T) {
	m := NewModel(HomeState{Running: true, TUNAvailable: true})
	m.Hooks.SetSystemProxy = func(bool) error { return errors.New("proxy denied") }
	m.Hooks.SetTUN = func(bool) error { return errors.New("tun denied") }
	m.Hooks.SetAutoLaunch = func(bool) error { return errors.New("startup denied") }
	m.Router.Replace("/settings")
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	for _, id := range []string{"sysproxy-row", "tun-row", "launch-row"} {
		if err := tt.Click(id); err != nil {
			t.Fatal(err)
		}
	}
	if m.Home.SystemProxy || m.Home.TUN || m.Prefs.AutoLaunch {
		t.Fatalf("failed changes were shown as enabled: %+v %+v", m.Home, m.Prefs)
	}
}
