package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestProfileProxyUpdateBusyAndFailure(t *testing.T) {
	m := NewModel(HomeState{})
	var done func(error)
	var calls int
	m.Hooks.UpdateProfileViaProxyAsync = func(uid string, finish func(error)) {
		if uid != "profile" {
			t.Fatalf("wrong profile %q", uid)
		}
		calls++
		done = finish
	}
	m.updateProfileViaProxy("profile")
	m.updateProfileViaProxy("profile")
	if !m.ProfileBusy || calls != 1 || done == nil {
		t.Fatal("proxy update did not serialize")
	}
	done(errors.New("proxy unavailable"))
	if m.ProfileBusy || !strings.Contains(m.Notice, "proxy unavailable") {
		t.Fatal("proxy failure not shown")
	}
}
