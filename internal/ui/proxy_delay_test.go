package ui

import (
	"errors"
	"testing"
)

func TestProxyDelayAndHomeSelectionUseKernelHooks(t *testing.T) {
	m := NewModel(HomeState{Mode: "rule"})
	m.CurrentProfile = "p1"
	m.Groups = []ProxyGroup{{Name: "A", Type: "Selector", Now: "one", Nodes: []ProxyNode{{Name: "one", Delay: -1}, {Name: "two", Delay: -1}}}, {Name: "B", Type: "URLTest", Now: "three", Nodes: []ProxyNode{{Name: "three", Delay: -1}}}}
	m.Home.Node = CurrentNode{Group: "A", Name: "one", Delay: -1}
	var selectedGroup, selectedNode string
	m.Hooks.SelectProxy = func(group, node string) error { selectedGroup, selectedNode = group, node; return nil }
	m.selectHomeNode("two")
	if selectedGroup != "A" || selectedNode != "two" || m.Groups[0].Now != "two" {
		t.Fatal("home selector did not update the kernel")
	}
	m.selectHomeGroup("B")
	if m.Home.Node.Name != "three" || m.Home.Node.Group != "B" {
		t.Fatalf("wrong home group: %+v", m.Home.Node)
	}
	var finish func(int, error)
	m.Hooks.TestProxyAsync = func(group, name, url string, done func(int, error)) {
		if name != "three" || url != defaultDelayURL {
			t.Fatalf("delay request %s %s", name, url)
		}
		finish = done
	}
	m.testProxyDelay("B", "three", "")
	if m.Home.Node.Delay != DelayTesting || m.Groups[1].Nodes[0].Delay != DelayTesting {
		t.Fatal("testing state absent")
	}
	finish(42, nil)
	if m.Home.Node.Delay != 42 || m.Groups[1].Nodes[0].Delay != 42 {
		t.Fatal("delay result not propagated")
	}
	m.Hooks.SelectProxy = func(string, string) error { return errors.New("select failed") }
	m.selectHomeGroup("A")
	m.selectHomeNode("one")
	if m.Groups[0].Now != "two" || m.Notice != "select failed" {
		t.Fatal("failed selection did not roll back")
	}
}
