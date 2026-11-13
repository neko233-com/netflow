package ui

import (
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	mygoui "github.com/egoist/mygo/ui"
)

// TestTwoRuneButtonsHaveNoInsertedSpace locks the #9 fix for labels such
// as 「订阅」. A two-character button is the two characters and nothing
// between them. 「订 阅」 fails this test.
func TestTwoRuneButtonsHaveNoInsertedSpace(t *testing.T) {
	buttons := []string{
		"首页", "代理", "订阅", "连接", "规则", "日志", "测试", "设置",
		"轻量", "手册", "测速", "导入", "新建", "粘贴", "清除", "批量",
		"更新", "配置", "激活", "刷新", "全局", "直连", "定位",
		"复制", "浏览", "浅色", "深色", "系统",
	}
	frames := []*mygoui.Tester{
		renderModel(DemoModel(), WindowWidth, WindowHeight, false),
		profileFrame(t, ""),
		profileFrame(t, "https://example.com/sub"),
		proxiesFrame(t),
		settingsFrame(t),
	}
	seen := map[string]bool{}
	for _, tt := range frames {
		texts := tt.Texts()
		for _, label := range buttons {
			spaced := spacedPair(label)
			for _, text := range texts {
				if text == spaced {
					t.Errorf("button %q is drawn as %q", label, text)
				}
				if text == label {
					seen[label] = true
				}
			}
		}
	}
	for _, label := range buttons {
		if !seen[label] {
			t.Errorf("two-character button %q was not drawn", label)
		}
	}
}

func profileFrame(t *testing.T, url string) *mygoui.Tester {
	t.Helper()
	m := DemoModel()
	m.ProfileURL = url
	m.Router.Replace("/profile")
	return renderModel(m, WindowWidth, WindowHeight, false)
}

func proxiesFrame(t *testing.T) *mygoui.Tester {
	t.Helper()
	m := DemoModel()
	m.Router.Replace("/proxies")
	return renderModel(m, WindowWidth, WindowHeight, false)
}

func settingsFrame(t *testing.T) *mygoui.Tester {
	t.Helper()
	m := DemoModel()
	m.Router.Replace("/settings")
	// Tall enough that every settings row is laid out, including the ones
	// below the 700px fold.
	return renderModel(m, WindowWidth, 1600, false)
}

func spacedPair(s string) string {
	r := []rune(s)
	if len(r) != 2 {
		return s
	}
	return string(r[0]) + " " + string(r[1])
}

// TestSettingsValueSpaceChevron checks every clickable settings row.
// The chevron is to the right of that row's trail. A row that shows a
// value must draw the value, then a space, then 「›」.
//
// ui.NewTester.Find returns the first match, and 「›」 is repeated, so the
// boxes come from the tester's label list (mygo v0.7.4).
//
// Plain trails (端口设置 「7897」, and 「?」 on 备份设置, 配置目录, and
// 轻量模式设置) use the same gap as padded ones (CORS, 齿轮).
func TestSettingsValueSpaceChevron(t *testing.T) {
	tt := settingsFrame(t)
	trails := chevronTrails(t, tt)
	want := []string{"未安装", "7897", "CORS", "网页界面", "core-gear"}
	if runtime.GOOS == "windows" {
		want = append(want, "UWP 工具")
	}
	want = append(want,
		"更新 GeoData", "流量隧道管理",
		"主题设置", "界面设置", "杂项设置", "热键设置",
		"help-backup", "当前配置", "help-conf", "内核目录", "日志目录", "检查更新", "开发者工具", "help-lite", "退出",
	)
	got := make([]string, len(trails))
	for i, tr := range trails {
		got[i] = tr.text
	}
	if !sameStrings(got, want) {
		t.Fatalf("settings chevron trails %q, want %q", got, want)
	}

	const space float32 = 4 // about one space at the 13px value size
	var other []string
	sawPort := false
	for _, tr := range trails {
		if tr.chev.W <= 0 || tr.prev.W <= 0 {
			other = append(other, tr.text+" has no box")
			continue
		}
		if !overlapsY(tr.prev.Y, tr.prev.H, tr.chev.Y, tr.chev.H) || tr.prev.X >= tr.chev.X {
			other = append(other, tr.text+" chevron is not to the right")
			continue
		}
		if settingsRowTitle(tr.text) {
			continue
		}
		gap := tr.chev.X - (tr.prev.X + tr.prev.W)
		if tr.text == "7897" {
			sawPort = true
		}
		if gap >= space {
			continue
		}
		other = append(other, tr.text)
	}
	if len(other) > 0 {
		t.Fatalf("settings value must be followed by a space then › (gap >= %v): %v", space, other)
	}
	if !sawPort {
		t.Fatal("端口设置 value 7897 was not measured")
	}
}

func settingsRowTitle(s string) bool {
	switch s {
	case "网页界面", "更新 GeoData", "流量隧道管理", "UWP 工具",
		"主题设置", "界面设置", "杂项设置", "热键设置",
		"当前配置", "内核目录", "日志目录", "检查更新", "开发者工具", "退出":
		return true
	default:
		return false
	}
}

type chevronTrail struct {
	text string
	prev mygoui.Rect
	chev mygoui.Rect
}

func chevronTrails(t *testing.T, tt *mygoui.Tester) []chevronTrail {
	t.Helper()
	nodes := testerLabels(t, tt)
	var out []chevronTrail
	for i, n := range nodes {
		if n.text != "›" || i == 0 {
			continue
		}
		prev := nodes[i-1]
		out = append(out, chevronTrail{text: prev.text, prev: prev.r, chev: n.r})
	}
	if len(out) == 0 {
		t.Fatal("settings frame has no ›")
	}
	return out
}

type testerLabel struct {
	text string
	r    mygoui.Rect
}

// testerLabels reads every labeled box. Find only returns the first.
func testerLabels(t *testing.T, tt *mygoui.Tester) []testerLabel {
	t.Helper()
	rv := reflect.ValueOf(tt).Elem()
	rt := exposeField(rv.FieldByName("rt"))
	if !rt.IsValid() || rt.Kind() != reflect.Pointer {
		t.Fatal("tester has no runtime")
	}
	labels := exposeField(rt.Elem().FieldByName("labels"))
	if !labels.IsValid() || labels.Kind() != reflect.Slice {
		t.Fatal("tester runtime has no label list")
	}
	out := make([]testerLabel, 0, labels.Len())
	for i := 0; i < labels.Len(); i++ {
		n := exposeField(labels.Index(i))
		text := n.FieldByName("text")
		rect := exposeField(n.FieldByName("r"))
		if !text.IsValid() || !rect.IsValid() {
			t.Fatal("label node has no text or rect")
		}
		out = append(out, testerLabel{text: text.String(), r: rect.Interface().(mygoui.Rect)})
	}
	return out
}

func exposeField(v reflect.Value) reflect.Value {
	if !v.IsValid() || v.CanInterface() {
		return v
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func overlapsY(y, h, y2, h2 float32) bool {
	return y < y2+h2 && y2 < y+h
}
