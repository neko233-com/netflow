package ui

import (
	"image"
	"testing"

	"github.com/neko233-com/netflow/internal/rules"
	"github.com/neko233-com/netflow/internal/unlock"

	mygoui "github.com/egoist/mygo/ui"
)

// TestM5MediumUnlock fixes the unlock-page diffs from issue #10: the
// second title, the test-all refresh icon, the per-card round refresh,
// the pending chip icon, and one right-aligned "-- --".
func TestM5MediumUnlock(t *testing.T) {
	names := unlock.Names()
	if len(names) < 2 || names[1] != "哔哩哔哩港澳台" {
		t.Fatalf("second unlock item %q", names)
	}
	m := NewModel(demoHome())
	m.Router.Replace("/unlock")
	var calls []string
	m.Hooks.CheckUnlock = func(name string) (string, string, int, error) {
		calls = append(calls, name)
		return "Yes", "US", 40, nil
	}
	tt := renderModel(m, WindowWidth, 1400, false)
	if !hasExactText(tt, "哔哩哔哩港澳台") {
		t.Fatal("missing 哔哩哔哩港澳台")
	}
	if hasExactText(tt, "港澳台") {
		t.Fatal("card title is still the short 港澳台")
	}
	if exactCount(tt, "--") != 0 {
		t.Fatalf("untested cards still have a lone -- line: %q", tt.Texts())
	}
	if !tt.HasText("测试全部") || !tt.HasText("-- --") || !tt.HasText("待检测") {
		t.Fatalf("unlock texts %q", tt.Texts())
	}

	card, okCard := tt.Find("unlock-哔哩哔哩大陆")
	btn, okBtn := tt.Find("unlock-test-哔哩哔哩港澳台")
	card2, okCard2 := tt.Find("unlock-哔哩哔哩港澳台")
	if !okCard || !okBtn || !okCard2 {
		t.Fatalf("card %v btn %v second %v", okCard, okBtn, okCard2)
	}
	if !near(btn.W, 32, 1) || !near(btn.H, 32, 1) {
		t.Fatalf("per-card refresh should be 32px, got %v", btn)
	}
	if gap := (card2.X + card2.W) - (btn.X + btn.W); gap < 4 || gap > 20 || btn.Y > card2.Y+18 {
		t.Fatalf("refresh should sit in the card's top right, btn %v card %v", btn, card2)
	}

	all, okAll := tt.Find("unlock-all")
	icon, okIcon := tt.Find("unlock-all-icon")
	word, okWord := tt.Find("测试全部")
	if !okAll || !okIcon || !okWord {
		t.Fatalf("test-all button %v icon %v word %v", okAll, okIcon, okWord)
	}
	if icon.X < all.X || word.X <= icon.X || icon.X+icon.W > all.X+all.W {
		t.Fatalf("RefreshRounded should lead 测试全部, icon %v word %v button %v", icon, word, all)
	}
	if icon.W < 16 || icon.W > 20 {
		t.Fatalf("test-all icon size %v", icon)
	}

	chip, okChip := tt.Find("unlock-chip-哔哩哔哩大陆")
	mark, okMark := tt.Find("unlock-status-哔哩哔哩大陆")
	if !okChip || !okMark {
		t.Fatal("pending chip or icon missing")
	}
	if chip.W > card.W*0.6 || chip.X+chip.W > card.X+card.W-40 {
		t.Fatalf("pending chip is still a full-width bar, chip %v card %v", chip, card)
	}
	if mark.W < 14 || mark.H < 14 {
		t.Fatalf("pending icon %v", mark)
	}

	when, okWhen := tt.Find("-- --")
	if !okWhen {
		t.Fatal("missing -- --")
	}
	if when.H > 22 {
		t.Fatalf("-- -- wrapped onto two lines, h %v", when.H)
	}
	rightGap := (card.X + card.W) - (when.X + when.W)
	if rightGap < 4 || rightGap > 24 || when.X < card.X+card.W*0.45 {
		t.Fatalf("-- -- should be one right-aligned line, time %v card %v", when, card)
	}

	// The card body is not the control. The round refresh is.
	tt.ClickAt(card.X+24, card.Y+card.H/2)
	if len(calls) != 0 {
		t.Fatalf("clicking the card body started a check: %v", calls)
	}
	if err := tt.Click("unlock-test-ChatGPT Web"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "ChatGPT Web" || m.Unlocks[2].Status != "Yes" {
		t.Fatalf("refresh click calls %v card %+v", calls, m.Unlocks[2])
	}

	m.Unlocks[0].Delay = -2
	m.Unlocks[0].Status = "Pending"
	tt = renderModel(m, WindowWidth, 1400, false)
	if _, ok := tt.Find("unlock-all-icon"); ok {
		t.Fatal("testing state kept the refresh icon")
	}
	spin, okSpin := tt.Find("unlock-all-spinner")
	if !okSpin || spin.W < 14 || spin.W > 18 || !tt.HasText("测试中...") {
		t.Fatalf("testing button spinner %v ok %v", spin, okSpin)
	}
	if err := tt.Click("unlock-test-" + names[0]); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("in-progress card accepted another check: %v", calls)
	}
}

func TestM5MediumConnectionsLayout(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/connections")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if tt.HasText("列表视图") || tt.HasText("表格视图") {
		t.Fatalf("layout toggle is still text: %q", tt.Texts())
	}
	btn, okBtn := tt.Find("conn-layout")
	rows, okRows := tt.Find("conn-layout-rows")
	if !okBtn || !okRows {
		t.Fatalf("table layout icon missing btn %v rows %v", okBtn, okRows)
	}
	if _, ok := tt.Find("conn-layout-chart"); ok {
		t.Fatal("table layout showed the table-chart icon")
	}
	if !near(btn.W, iconButtonSmall, 1) || !near(btn.H, iconButtonSmall, 1) || !near(rows.W, iconGlyphSmall, 1.5) {
		t.Fatalf("layout button %v icon %v, want %v/%v", btn, rows, iconButtonSmall, iconGlyphSmall)
	}
	if err := tt.Click("conn-layout"); err != nil {
		t.Fatal(err)
	}
	if m.Conns.Layout != "list" {
		t.Fatalf("layout %q", m.Conns.Layout)
	}
	if _, ok := tt.Find("conn-layout-chart"); !ok {
		t.Fatal("list layout missing TableChartRounded")
	}
	if _, ok := tt.Find("conn-layout-rows"); ok {
		t.Fatal("list layout kept TableRowsRounded")
	}
	if tt.HasText("列表视图") || tt.HasText("表格视图") {
		t.Fatal("toggle gained a text label after the switch")
	}
}

func TestM5MediumLogsPause(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/logs")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	btn, okBtn := tt.Find("log-pause")
	icon, okIcon := tt.Find("log-pause-icon")
	order, okOrder := tt.Find("log-order")
	if !okBtn || !okIcon || !okOrder {
		t.Fatalf("pause %v icon %v order %v", okBtn, okIcon, okOrder)
	}
	if !near(btn.W, 34, 1) || !near(btn.H, 34, 1) || !near(icon.W, 20, 1.5) || !near(icon.H, 20, 1.5) {
		t.Fatalf("pause button %v icon %v, want about 34/20", btn, icon)
	}
	if order.W > 30 {
		t.Fatalf("sort control changed size %v", order)
	}
	if !circleTopInk(tt.Image(), icon) {
		_ = writePNG("/tmp/log-pause.png", tt.Image())
		t.Fatal("pause glyph has no circle at the top; wrote /tmp/log-pause.png")
	}
	if err := tt.Click("log-pause"); err != nil {
		t.Fatal(err)
	}
	if !m.Logs.Paused {
		t.Fatal("pause click did not pause")
	}
	icon, okIcon = tt.Find("log-pause-icon")
	btn, _ = tt.Find("log-pause")
	if !okIcon || !near(btn.W, 34, 1) || !near(icon.W, 20, 1.5) || !circleTopInk(tt.Image(), icon) {
		t.Fatalf("resume glyph lost the circle, button %v icon %v", btn, icon)
	}
}

func TestM5MediumRuleProviderButton(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/rules")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if tt.HasText("规则集合") {
		t.Fatal("empty rules page showed 规则集合")
	}
	if _, ok := tt.Find("rule-providers"); ok {
		t.Fatal("empty rules page showed the provider button")
	}

	m.Rules.Loaded = false
	m.Rules.Providers = []rules.Provider{{Name: "local", Count: 4, Vehicle: "File", Behavior: "classical", UpdatedAt: "1 天前"}}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	btn, okBtn := tt.Find("rule-providers")
	icon, okIcon := tt.Find("rule-providers-icon")
	word, okWord := tt.Find("规则集合")
	if !okBtn || !okIcon || !okWord {
		t.Fatalf("provider button %v icon %v text %v", okBtn, okIcon, okWord)
	}
	if btn.W < 72 || btn.H < 26 || btn.H > 34 {
		t.Fatalf("provider control should be an outlined text button, got %v", btn)
	}
	if icon.X < btn.X || word.X <= icon.X || word.X+word.W > btn.X+btn.W+1 {
		t.Fatalf("StorageOutlined should lead 规则集合, icon %v word %v button %v", icon, word, btn)
	}
	if btn.Y > 58 || btn.X < sidebarExpandedWidth {
		t.Fatalf("provider button left the header %v", btn)
	}
	if err := tt.Click("rule-providers"); err != nil {
		t.Fatal(err)
	}
	if !m.Rules.Open {
		t.Fatal("provider button did not open the dialog")
	}
}

func exactCount(tt *mygoui.Tester, s string) int {
	n := 0
	for _, text := range tt.Texts() {
		if text == s {
			n++
		}
	}
	return n
}

func near(got, want, slop float32) bool {
	return got >= want-slop && got <= want+slop
}

// circleTopInk reports whether the icon's top center carries paint.
// PauseCircleOutlineRounded does. Two bare pause bars do not: they sit
// left and right of the center.
func circleTopInk(img image.Image, icon mygoui.Rect) bool {
	if img == nil || icon.W < 8 || icon.H < 8 {
		return false
	}
	cx := icon.X + icon.W/2
	top := icon.Y + icon.H*(1.5/24)
	bot := icon.Y + icon.H*(6.0/24)
	for y := top; y <= bot; y += 0.5 {
		for _, dx := range []float32{-1, -0.5, 0, 0.5, 1} {
			if ink(img, cx+dx, y) {
				return true
			}
		}
	}
	return false
}

func ink(img image.Image, x, y float32) bool {
	b := img.Bounds()
	px, py := int(x), int(y)
	if px < b.Min.X || py < b.Min.Y || px >= b.Max.X || py >= b.Max.Y {
		return false
	}
	r, g, bl, a := img.At(px, py).RGBA()
	if a>>8 < 30 {
		return false
	}
	lum := (r + g + bl) / 3 >> 8
	return lum < 180
}
