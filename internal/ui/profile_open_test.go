package ui

import (
	"errors"
	"testing"
)

func TestOpenProfileFileUsesSelectedID(t *testing.T) {
	m := NewModel(HomeState{})
	var selected string
	m.Hooks.OpenProfileFile = func(id string) error { selected = id; return nil }
	m.openProfileFile("profile-two")
	if selected != "profile-two" || m.Notice == "" {
		t.Fatal("wrong profile file opened")
	}
	m.Hooks.OpenProfileFile = func(string) error { return errors.New("open failed") }
	m.openProfileFile("profile-two")
	if m.Notice != "open failed" {
		t.Fatal("open error not shown")
	}
}
