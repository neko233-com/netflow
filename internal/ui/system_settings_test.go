package ui

import (
	"errors"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestSystemSettingsRestoreSwitchAfterFailure(t *testing.T) {
	m := NewModel(HomeState{Running: true, TUNAvailable: true})
	m.Hooks.SetTUN = func(bool) error { return errors.New("tun denied") }
	m.Hooks.SetAutoLaunch = func(bool) error { return errors.New("startup denied") }
	m.Router.Replace("/settings")
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	for _, id := range []string{"tun-row", "launch-row"} {
		if err := tt.Click(id); err != nil {
			t.Fatal(err)
		}
	}
	if m.Home.SystemProxy || m.Home.TUN || m.Prefs.AutoLaunch {
		t.Fatalf("failed changes were shown as enabled: %+v %+v", m.Home, m.Prefs)
	}
}

func TestTUNAutoStartPreferenceDoesNotToggleCurrentTUN(t *testing.T) {
	m := NewModel(HomeState{Running: true, TUNAvailable: true})
	tunCalls := 0
	m.Hooks.SetTUN = func(bool) error { tunCalls++; return nil }
	m.Hooks.SetTUNAutoStart = func(bool) error { return errors.New("save failed") }
	m.Router.Replace("/settings")
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("tun-autostart-row"); err != nil {
		t.Fatal(err)
	}
	if m.Prefs.AutoStartTUN || tunCalls != 0 {
		t.Fatal("failed preference changed state or TUN")
	}
	m.Hooks.SetTUNAutoStart = func(on bool) error {
		if !on {
			t.Error("unexpected preference")
		}
		return nil
	}
	if err := tt.Click("tun-autostart-row"); err != nil {
		t.Fatal(err)
	}
	if !m.Prefs.AutoStartTUN || m.Home.TUN || tunCalls != 0 {
		t.Fatal("preference toggled current TUN")
	}
}
