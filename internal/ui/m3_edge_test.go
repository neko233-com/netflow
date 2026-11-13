package ui

import (
	"testing"

	"github.com/neko233-com/netflow/internal/conn"
)

// TestClearClosedLeavesActive is the closed-tab Fab. 「清除」 drops the
// closed list and must not close or remove a connection that is still active.
func TestClearClosedLeavesActive(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/connections")
	m.Conns.Layout = "table"
	m.Conns.Tab = "closed"
	m.Conns.Active = []conn.Item{{ID: "live", Host: "still-open.example", DestinationPort: "443"}}
	m.Conns.Closed = []conn.Item{{ID: "old", Host: "already-closed.example", DestinationPort: "80"}}
	cleared := 0
	closedAll := 0
	closedOne := 0
	m.Hooks.ClearClosed = func() { cleared++ }
	m.Hooks.CloseAllConnections = func() error {
		closedAll++
		return nil
	}
	m.Hooks.CloseConnection = func(string) error {
		closedOne++
		return nil
	}

	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !hasExactText(tt, "清除") {
		t.Fatalf("closed tab fab is not 清除, texts %q", tt.Texts())
	}
	if !tt.HasText("already-closed.example") {
		t.Fatal("closed row is not listed")
	}
	if err := tt.Click("清除"); err != nil {
		t.Fatal(err)
	}
	if cleared != 1 || closedAll != 0 || closedOne != 0 {
		t.Fatalf("clear called close paths: cleared %d closeAll %d closeOne %d", cleared, closedAll, closedOne)
	}
	if len(m.Conns.Closed) != 0 {
		t.Fatalf("closed list %+v", m.Conns.Closed)
	}
	if len(m.Conns.Active) != 1 || m.Conns.Active[0].ID != "live" || m.Conns.Active[0].Host != "still-open.example" {
		t.Fatalf("active list changed: %+v", m.Conns.Active)
	}
	if err := tt.Click("活跃 1"); err != nil {
		t.Fatal(err)
	}
	if m.Conns.Tab == "closed" || !tt.HasText("still-open.example") {
		t.Fatalf("active row missing after clear, tab %q texts %q", m.Conns.Tab, tt.Texts())
	}
	if tt.HasText("already-closed.example") {
		t.Fatal("cleared connection came back on the active tab")
	}
}
