package ui

import (
	"errors"
	"testing"

	"github.com/neko233-com/netflow/internal/sitetest"
)

func TestUnlockPageGrid(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/unlock")
	var checked []string
	m.Hooks.CheckUnlock = func(name string) (string, string, int, error) {
		checked = append(checked, name)
		if name == "Netflix" {
			return "", "", 0, sitetest.ErrTimeout
		}
		if name == "Disney+" {
			return "", "", 0, errors.New("down")
		}
		return "Yes", "US", 40, nil
	}
	tt := renderModel(m, WindowWidth, 1400, false)
	if !tt.HasText("解锁测试") || !tt.HasText("测试全部") || !tt.HasText("哔哩哔哩大陆") || !tt.HasText("TikTok") {
		t.Fatalf("unlock texts %q", tt.Texts())
	}
	if len(m.Unlocks) != 13 {
		t.Fatalf("cards %d", len(m.Unlocks))
	}
	if err := tt.Click("unlock-test-Netflix"); err != nil {
		t.Fatal(err)
	}
	if m.Notice != "检测超时或失败" || m.Unlocks[8].Status == "Pending" || m.Unlocks[8].Delay == -2 {
		t.Fatalf("netflix %+v notice %q", m.Unlocks[8], m.Notice)
	}
	if err := tt.Click("unlock-test-Disney+"); err != nil {
		t.Fatal(err)
	}
	if m.Notice != "Disney+ 检测失败" {
		t.Fatalf("notice %q", m.Notice)
	}
	if err := tt.Click("unlock-all"); err != nil {
		t.Fatal(err)
	}
	if len(checked) < 13 {
		t.Fatalf("checked %d", len(checked))
	}
	if m.Unlocks[2].Status != "Yes" || m.Unlocks[2].Region != "US" || !tt.HasText("支持") {
		t.Fatalf("chatgpt %+v", m.Unlocks[2])
	}
}
