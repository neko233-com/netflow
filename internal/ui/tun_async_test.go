package ui

import (
	"errors"
	"testing"
)

func TestTUNAsyncDoesNotShowSuccessUntilCompleted(t *testing.T) {
	m := NewModel(HomeState{TUNAvailable: true})
	var finish func(error)
	calls := 0
	m.Hooks.SetTUNAsync = func(on bool, done func(error)) { calls++; finish = done }
	m.setTUN(true)
	m.setTUN(true)
	if m.Home.TUN || m.Busy != "tun" || calls != 1 {
		t.Fatal("pending TUN request was shown as successful or duplicated")
	}
	finish(errors.New("permission denied"))
	if m.Home.TUN || m.Busy != "" || m.Notice != "permission denied" {
		t.Fatal("failed TUN request was not restored")
	}
	m.setTUN(true)
	finish(nil)
	if !m.Home.TUN || m.Busy != "" {
		t.Fatal("successful TUN request did not update the state")
	}
}
