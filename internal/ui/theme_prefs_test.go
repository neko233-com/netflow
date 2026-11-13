package ui

import (
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestCustomPaletteAndThemeDialogPersistence(t *testing.T) {
	p := DefaultPrefs()
	p.ThemePrimary = "#123456"
	p.ThemeWarning = "unfinished"
	got := PaletteWithPrefs(false, p)
	if got.Primary != mygoui.Hex("#123456") || got.Warning != PaletteFor(false).Warning {
		t.Fatal("valid custom color or invalid fallback was ignored")
	}
	m := NewModel(HomeState{})
	m.Prefs = p
	m.Router.Replace("/settings")
	m.Dialogs.Theme = true
	var saved Prefs
	calls := 0
	m.Hooks.SavePrefs = func(value Prefs) error { saved = value; calls++; return nil }
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if err := tt.Click("close-主题设置"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || saved.ThemePrimary != "#123456" {
		t.Fatalf("theme not saved: %d %+v", calls, saved)
	}
}
