package ui

import (
	"errors"
	"testing"
)

func TestRuntimeConfigUsesCoreAndHandlesErrors(t *testing.T) {
	m := NewModel(HomeState{})
	m.Hooks.LoadEffectiveConfig = func() (string, error) { return "mode: direct", nil }
	m.openRuntimeConfig()
	if !m.Dialogs.Runtime || m.RuntimeConfig != "mode: direct" {
		t.Fatal("runtime config not loaded")
	}
	m.Dialogs.Runtime = false
	m.Hooks.LoadEffectiveConfig = func() (string, error) { return "", errors.New("core stopped") }
	m.openRuntimeConfig()
	if m.Dialogs.Runtime || m.Notice != "core stopped" {
		t.Fatal("runtime failure not shown")
	}
}
