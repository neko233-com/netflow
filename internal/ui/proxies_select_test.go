package ui

import (
	"image"
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

// TestProxiesSelectNode drives /proxies without a window.
//
// The title is 「代理组」. ui.NewTester does not expose a text node's font
// size, so the 20px heading is the exported PageTitleSize.
//
// Clicking another node in a Selector group changes the selected row: the
// group's Now, the home node, the ✓ mark, and the 3px bar.
//
// This view test leaves Hooks.SelectProxy nil. The kernel write is
// TestSelectWritesSelector: it calls core.Core.Select and reads Now()
// from tunnel.Proxies, because CI's -race build does not listen on the
// external controller.
func TestProxiesSelectNode(t *testing.T) {
	if PageTitleSize != 20 {
		t.Fatalf("PageTitleSize %v, want 20", PageTitleSize)
	}
	m := NewModel(demoHome())
	m.Home.Running = true
	m.Profiles = []ProfileItem{{UID: "p1", Name: "sub", Type: "remote", URL: "https://example.com/sub"}}
	m.CurrentProfile = "p1"
	m.Prefs.ProxyColumns = 1
	m.Groups = []ProxyGroup{{
		Name: "PROXY", Type: "Selector", Now: "n1", Open: true,
		Nodes: []ProxyNode{
			{Name: "n1", Type: "direct", Delay: -1},
			{Name: "n2", Type: "direct", Delay: -1},
		},
	}}
	m.Home.Node = CurrentNode{Group: "PROXY", Name: "n1", Type: "direct", Delay: -1, Groups: []string{"PROXY"}}

	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("代理"); err != nil {
		t.Fatal(err)
	}
	settleTester(tt)
	if m.Router.Path() != "/proxies" {
		t.Fatalf("path %q, want /proxies", m.Router.Path())
	}
	if !hasExactText(tt, "代理组") {
		t.Fatalf("texts %q, want an exact 代理组 title", tt.Texts())
	}
	if m.Groups[0].Now != "n1" {
		t.Fatalf("now %q before the click", m.Groups[0].Now)
	}
	if err := tt.Click("n2"); err != nil {
		t.Fatal(err)
	}
	if m.Groups[0].Now != "n2" || m.Home.Node.Name != "n2" || m.Home.Node.Group != "PROXY" {
		t.Fatalf("after click group now %q home %+v", m.Groups[0].Now, m.Home.Node)
	}
	// The pointer is still over n2, and a hovered row draws 检测 instead of ✓.
	tt.Move(1, 1)
	settleTester(tt)
	if !hasExactText(tt, "✓") {
		t.Fatalf("selected row has no ✓, texts %q", tt.Texts())
	}
	selected, ok := tt.Find("node-PROXY-n2")
	if !ok {
		t.Fatal("selected row has no box")
	}
	if !selectionBar(tt.Image(), selected) {
		t.Fatalf("n2 row %v has no 3px selection bar", selected)
	}
	previous, ok := tt.Find("node-PROXY-n1")
	if !ok {
		t.Fatal("previous row has no box")
	}
	if selectionBar(tt.Image(), previous) {
		t.Fatalf("n1 row %v kept the selection bar", previous)
	}
}

// settleTester finishes a route change. The frame after a click can still
// be pending, and that frame paints only the content background.
func settleTester(tt *mygoui.Tester) {
	for i := 0; i < 5 && tt.FramePending(); i++ {
		tt.Advance(time.Second)
	}
}

// selectionBar reports whether the row's left edge is the primary 3px bar.
func selectionBar(img image.Image, row mygoui.Rect) bool {
	if img == nil {
		return false
	}
	x := int(row.X) + 1
	y := int(row.Y + row.H/2)
	b := img.Bounds()
	if x < b.Min.X || y < b.Min.Y || x >= b.Max.X || y >= b.Max.Y {
		return false
	}
	r, g, bl, _ := img.At(x, y).RGBA()
	// #007AFF, with a little room for the edge.
	return r>>8 < 0x30 && g>>8 > 0x50 && g>>8 < 0xA0 && bl>>8 > 0xE0
}
