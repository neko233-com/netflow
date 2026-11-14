package ui

import (
	"fmt"
	"testing"
	"time"
)

func TestLetterNavigationScrollsAndRespectsHoverDelay(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/proxies")
	m.Prefs.HoverNav = true
	m.Prefs.HoverDelay = 280
	m.Prefs.ProxyColumns = 1
	nodes := make([]ProxyNode, 25)
	for i := range nodes {
		nodes[i] = ProxyNode{Name: fmt.Sprintf("node-%d", i), Type: "Socks5", Delay: -1}
	}
	m.Groups = []ProxyGroup{{Name: "Alpha", Type: "Selector", Open: true, Nodes: nodes}, {Name: "Zulu", Type: "Selector", Open: false, Nodes: []ProxyNode{{Name: "end", Type: "Socks5"}}}}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	before, ok := tt.Find("group-Zulu")
	if !ok {
		t.Fatal("target group missing")
	}
	letter, ok := tt.Find("letter-Z")
	if !ok {
		t.Fatal("letter control missing")
	}
	tt.Move(letter.X+letter.W/2, letter.Y+letter.H/2)
	tt.Advance(279 * time.Millisecond)
	if m.Groups[1].Open {
		t.Fatal("hover opened group before configured delay")
	}
	tt.Advance(time.Millisecond)
	tt.Frame()
	after, ok := tt.Find("group-Zulu")
	if !ok || !m.Groups[1].Open {
		t.Fatal("hover did not open target group")
	}
	if after.Y >= before.Y || after.Y < 0 || after.Y > WindowHeight {
		t.Fatalf("target not scrolled into view: before=%+v after=%+v", before, after)
	}
	if err := tt.Click("letter-A"); err != nil {
		t.Fatalf("letter index did not stay visible: %v", err)
	}
	tt.Frame()
	first, ok := tt.Find("group-Alpha")
	if !ok || first.Y < 0 || first.Y > WindowHeight {
		t.Fatalf("could not jump back: %+v", first)
	}
}

func TestLetterNavigationClickWorksWhenHoverDisabled(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/proxies")
	m.Prefs.HoverNav = false
	m.Groups = []ProxyGroup{{Name: "Alpha", Type: "Selector", Open: true, Nodes: []ProxyNode{{Name: "one", Type: "Socks5"}}}, {Name: "Zulu", Type: "Selector", Open: false, Nodes: []ProxyNode{{Name: "two", Type: "Socks5"}}}}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	letter, ok := tt.Find("letter-Z")
	if !ok {
		t.Fatal("letter control missing")
	}
	tt.Move(letter.X+letter.W/2, letter.Y+letter.H/2)
	tt.Advance(time.Second)
	if m.Groups[1].Open {
		t.Fatal("disabled hover still navigated")
	}
	if err := tt.Click("letter-Z"); err != nil {
		t.Fatal(err)
	}
	if !m.Groups[1].Open {
		t.Fatal("click did not navigate")
	}
}
