package ui

import (
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

// TestSidebarLogoSizes locks the brand slot from docs/spec/outlines/layout.md
// and design-tokens.md §8.1. The mark is docs/spec/assets/brand/favicon.svg.
//
// Expanded: the favicon is 36×36 beside 「NetFlow」.
// Collapsed: NewCollapsedTester's rail is 72px, the logo area is 56×56 and
// centered in that rail, the same 36×36 favicon is centered in the area,
// and the wordmark is not drawn.
func TestSidebarLogoSizes(t *testing.T) {
	m := NewModel(demoHome())
	expanded := renderModel(m, WindowWidth, WindowHeight, false)
	side, ok := expanded.Find("sidebar")
	if !ok {
		t.Fatal("expanded frame has no sidebar")
	}
	if side.W != 200 {
		t.Fatalf("expanded sidebar width %v, want 200", side.W)
	}
	mark, ok := expanded.Find("netflow-mark")
	if !ok {
		t.Fatal("expanded sidebar has no favicon")
	}
	if mark.W != 36 || mark.H != 36 {
		t.Fatalf("expanded favicon %v, want 36×36", mark)
	}
	name, ok := expanded.Find("NetFlow")
	if !ok || !expanded.HasText("NetFlow") {
		t.Fatal("expanded sidebar is missing 「NetFlow」")
	}
	gap := name.X - (mark.X + mark.W)
	if gap < 4 || gap > 6 {
		t.Fatalf("wordmark gap %v, want about 5 (mark %v name %v)", gap, mark, name)
	}
	if name.Y+name.H <= mark.Y || mark.Y+mark.H <= name.Y {
		t.Fatalf("「NetFlow」 is not beside the favicon: mark %v name %v", mark, name)
	}
	if _, shown := expanded.Find("logo-slot"); shown {
		t.Fatal("expanded sidebar used the collapsed 56×56 logo area")
	}
	assertCyanMark(t, expanded.Image(), mark)

	collapsed := NewCollapsedTester(m, false)
	requireCollapsedBrand(t, collapsed)
	assertCollapsedLogoCenter(t, collapsed)
	requireCollapsedBrand(t, NewCollapsedTester(nil, true))
}

func assertCollapsedLogoCenter(t *testing.T, tt *mygoui.Tester) {
	t.Helper()
	got, ok := MeasureCollapsedBrand(tt)
	if !ok {
		t.Fatal("collapsed helper found no brand")
	}
	if got.SidebarW != 72 || got.SlotW != 56 || got.SlotH != 56 || got.MarkW != 36 || got.MarkH != 36 || got.Wordmark {
		t.Fatalf("collapsed brand %+v, want rail 72, slot 56×56, mark 36×36, no wordmark", got)
	}
	side, okSide := tt.Find("sidebar")
	slot, okSlot := tt.Find("logo-slot")
	mark, okMark := tt.Find("netflow-mark")
	if !okSide || !okSlot || !okMark {
		t.Fatal("collapsed frame is missing sidebar, logo-slot, or the favicon")
	}
	if _, ok := tt.Find("NetFlow"); ok {
		t.Fatal("collapsed sidebar still shows 「NetFlow」")
	}
	left := slot.X - side.X
	right := (side.X + side.W) - (slot.X + slot.W)
	if abs32(left-right) > 1 || left < 0 || right < 0 {
		t.Fatalf("56×56 logo area is not centered in the 72px rail: side %v slot %v", side, slot)
	}
	mx, my := rectCenter(mark)
	sx, sy := rectCenter(slot)
	if abs32(mx-sx) > 0.5 || abs32(my-sy) > 0.5 {
		t.Fatalf("favicon center (%v,%v) is not the center of the 56×56 area (%v,%v)", mx, my, sx, sy)
	}
	assertCyanMark(t, tt.Image(), mark)
}

func rectCenter(r mygoui.Rect) (float32, float32) {
	return r.X + r.W/2, r.Y + r.H/2
}

func abs32(v float32) float32 {
	if v < 0 {
		return -v
	}
	return v
}
