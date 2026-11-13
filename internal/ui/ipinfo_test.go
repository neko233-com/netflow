package ui

import (
	"testing"

	"github.com/neko233-com/netflow/internal/ipinfo"
)

func TestIPRefreshRequiresUserActionAndUsesTimedRefresh(t *testing.T) {
	m := NewModel(HomeState{})
	calls := 0
	var finish func(ipinfo.Result, error)
	m.Hooks.QueryIPAsync = func(done func(ipinfo.Result, error)) { calls++; finish = done }
	m.TickIP()
	if calls != 0 {
		t.Fatal("queried IP without user action")
	}
	m.refreshIP()
	if calls != 1 || !m.IPBusy {
		t.Fatal("manual query did not start")
	}
	finish(ipinfo.Result{IP: "203.0.113.8", Country: "Example"}, nil)
	if m.IPBusy || !m.IP.Loaded || m.IP.IP != "203.0.113.8" {
		t.Fatal("IP result not shown")
	}
	m.IPAuto = true
	m.IPLeft = 2
	m.TickIP()
	if calls != 1 {
		t.Fatal("refresh ran early")
	}
	m.TickIP()
	if calls != 2 || m.IPLeft != 30 {
		t.Fatal("timed refresh did not run")
	}
}
