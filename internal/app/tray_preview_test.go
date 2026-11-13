package app

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

func TestTrayMenuPreview(t *testing.T) {
	dir := os.Getenv("CLASHGO_SCREENSHOT_DIR")
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, theme := range []struct {
		name string
		dark bool
	}{{"light", false}, {"dark", true}} {
		tt := mygoui.NewTester(TrayMenuView(TrayPreviewSnapshot(), theme.dark), 560, 420)
		tt.SetScale(1)
		tt.SetDark(theme.dark)
		for i := 0; i < 5 && tt.FramePending(); i++ {
			tt.Advance(time.Second)
		}
		for _, label := range []string{"仪表板", "出站模式 (规则)", "订阅", "TUN 模式", "退出 ⌘Q", "规则模式", "全局模式", "直连模式"} {
			if !tt.HasText(label) {
				t.Errorf("%s menu missing %q", theme.name, label)
			}
		}
		if tt.HasText("打开面板") || tt.HasText("测试延迟") {
			t.Fatalf("%s menu has a retired item: %q", theme.name, tt.Texts())
		}
		first, ok := tt.Find("仪表板")
		modes, okM := tt.Find("出站模式 (规则)")
		if !ok || !okM || first.Y >= modes.Y {
			t.Fatalf("仪表板 should lead the menu, dash %v modes %v", first, modes)
		}
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, "tray-"+theme.name+".png")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, tt.Image())
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}
