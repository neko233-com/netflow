package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/rules"
)

func TestProviderUpdatesAreAsynchronousAndReportPartialFailure(t *testing.T) {
	m := NewModel(HomeState{})
	var order []string
	var finish func(error)
	m.Hooks.UpdateProxyProviderAsync = func(name string, done func(error)) { order = append(order, name); finish = done }
	m.updateProxyProviders([]string{"a", "b"})
	if !m.ProviderBusy || len(order) != 1 {
		t.Fatal("provider update did not start")
	}
	finish(nil)
	if len(order) != 2 || order[1] != "b" {
		t.Fatal("provider update did not continue")
	}
	finish(errors.New("network"))
	if m.ProviderBusy || !strings.Contains(m.Notice, "失败") {
		t.Fatalf("result %q", m.Notice)
	}
	m.Rules.Providers = []rules.Provider{{Name: "rule-a"}, {Name: "rule-b"}}
	order = nil
	m.Hooks.UpdateRuleProviderAsync = func(name string, done func(error)) { order = append(order, name); finish = done }
	m.updateAllRules()
	if !m.Rules.Updating || len(order) != 1 {
		t.Fatal("rule update did not start")
	}
	finish(nil)
	finish(nil)
	if m.Rules.Updating || len(order) != 2 {
		t.Fatal("rule updates did not complete")
	}
}
