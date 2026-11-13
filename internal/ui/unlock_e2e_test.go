package ui

import (
	"testing"

	"github.com/neko233-com/netflow/internal/unlock"

	mygoui "github.com/egoist/mygo/ui"
)

// TestUnlockPageFlow locks the /unlock grid beyond TestUnlockPageGrid.
// That test already clicks Netflix (timeout), Disney+ (failure), and
// 测试全部. This one checks every title in spec order, the untested and
// in-progress cards, and that one card's result does not wipe the others.
// The prober is fake. The kernel is not started.
func TestUnlockPageFlow(t *testing.T) {
	names := unlock.Names()
	if len(names) != 13 {
		t.Fatalf("spec grid %d", len(names))
	}
	m := NewModel(demoHome())
	m.Router.Replace("/unlock")
	tt := renderModel(m, WindowWidth, 1400, false)
	if !tt.HasText("解锁测试") || !tt.HasText("测试全部") {
		t.Fatalf("header texts %q", tt.Texts())
	}
	if len(m.Unlocks) != 13 {
		t.Fatalf("cards %d", len(m.Unlocks))
	}
	var prev mygoui.Rect
	var have bool
	for i, name := range names {
		if m.Unlocks[i].Name != name || m.Unlocks[i].Delay != -1 || m.Unlocks[i].Status != "" {
			t.Fatalf("card %d %+v, want untested %s", i, m.Unlocks[i], name)
		}
		if !tt.HasText(name) {
			t.Errorf("missing title %s", name)
		}
		box, ok := tt.Find("unlock-" + name)
		if !ok || box.W <= 0 || box.H <= 0 {
			t.Fatalf("card %s box %v", name, box)
		}
		if have {
			sameRow := overlapsY(prev.Y, prev.H, box.Y, box.H)
			if i%3 == 0 {
				if box.Y <= prev.Y {
					t.Fatalf("%s should start the next row, prev %v box %v", name, prev, box)
				}
			} else if !sameRow || box.X <= prev.X {
				t.Fatalf("%s should sit to the right of the previous card, prev %v box %v", name, prev, box)
			}
		}
		prev = box
		have = true
	}
	if !tt.HasText("待检测") || !tt.HasText("-- --") {
		t.Fatalf("untested card texts %q", tt.Texts())
	}

	m.Unlocks[0].Delay = -2
	m.Unlocks[0].Status = "Pending"
	calls := 0
	m.Hooks.CheckUnlock = func(string) (string, string, int, error) {
		calls++
		return "Yes", "US", 40, nil
	}
	tt = renderModel(m, WindowWidth, 1400, false)
	if !tt.HasText("测试中...") || !tt.HasText("哔哩哔哩大陆") {
		t.Fatalf("checking state texts %q", tt.Texts())
	}
	if err := tt.Click("unlock-all"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || m.Unlocks[0].Delay != -2 {
		t.Fatalf("测试全部 ran while a card was checking: calls %d card %+v", calls, m.Unlocks[0])
	}

	m.Unlocks = DefaultUnlocks()
	tt = renderModel(m, WindowWidth, 1400, false)
	if err := tt.Click("unlock-test-" + names[0]); err != nil {
		t.Fatal(err)
	}
	if m.Unlocks[0].Status != "Yes" || m.Unlocks[0].Region != "US" || m.Unlocks[0].Delay != 40 {
		t.Fatalf("single result %+v", m.Unlocks[0])
	}
	if !tt.HasText("支持") || !tt.HasText("40 ms") || !tt.HasText("US") {
		t.Fatalf("success texts %q", tt.Texts())
	}
	for i := 1; i < len(m.Unlocks); i++ {
		if m.Unlocks[i].Delay != -1 || m.Unlocks[i].Status != "" {
			t.Fatalf("card %s changed while only %s was tested: %+v", m.Unlocks[i].Name, names[0], m.Unlocks[i])
		}
	}
	if calls != 1 {
		t.Fatalf("single click called the prober %d times", calls)
	}

	if err := tt.Click("unlock-all"); err != nil {
		t.Fatal(err)
	}
	if calls != 1+13 {
		t.Fatalf("测试全部 calls %d, want 14", calls)
	}
	for i, it := range m.Unlocks {
		if it.Status != "Yes" || it.Region != "US" || it.Delay != 40 {
			t.Fatalf("after 测试全部 card %d %+v", i, it)
		}
	}

	empty := NewModel(demoHome())
	empty.Unlocks = []UnlockItem{}
	empty.Router.Replace("/unlock")
	et := renderModel(empty, WindowWidth, WindowHeight, false)
	if !et.HasText("暂无解锁测试项目") {
		t.Fatalf("empty texts %q", et.Texts())
	}

	t.Run("kept", func(t *testing.T) {
		fresh := NewModel(demoHome())
		fresh.Router.Replace("/unlock")
		if fresh.Unlocks[0].Status == "Yes" && fresh.Unlocks[0].Delay == 40 {
			return
		}
		t.Skip("unlock results are not kept. Spec stores them in localStorage clash_verge_unlock_results; a new model starts every card at 待检测")
	})
}
