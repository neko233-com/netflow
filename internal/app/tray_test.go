package app

import (
	"strings"
	"testing"

	"github.com/egoist/mygo"
)

func TestTrayOrderHasNoDelayTest(t *testing.T) {
	menu := BuildTrayMenu(TraySnapshot{
		Mode:        "rule",
		SystemProxy: true,
		Version:     "0.2.1",
		Profiles:    []TrayProfile{{Name: "示例", Current: true}},
		Groups:      []TrayGroup{{Name: "Proxy", Now: "香港 01", Nodes: []string{"香港 01", "DIRECT"}}},
	}, TrayActions{})
	labels := menuLabels(menu.Items())
	joined := strings.Join(labels, "\n")
	if strings.Contains(joined, "测试延迟") || strings.Contains(joined, "延迟测试") {
		t.Fatalf("delay test returned to the tray:\n%s", joined)
	}
	want := []string{"仪表板", "出站模式 (规则)", "规则模式", "全局模式", "直连模式", "订阅", "示例", "代理", "Proxy", "香港 01", "系统代理", "TUN 模式", "轻量模式", "打开目录", "配置目录", "内核目录", "日志目录", "应用日志", "内核日志", "更多", "复制环境变量", "关闭全部连接", "重启内核", "重启应用", "NetFlow 版本 v0.2.1", "退出 ⌘Q"}
	for _, label := range want {
		if !strings.Contains(joined, label) {
			t.Errorf("missing %q\n%s", label, joined)
		}
	}
	top := topLabels(menu.Items())
	order := []string{"仪表板", "出站模式 (规则)", "订阅", "代理", "系统代理", "TUN 模式", "轻量模式", "打开目录", "更多", "退出 ⌘Q"}
	if strings.Join(top, "|") != strings.Join(order, "|") {
		t.Fatalf("order %v", top)
	}
	proxy := menu.ItemByID("system-proxy")
	if proxy == nil || !proxy.Checked {
		t.Fatal("system proxy should be checked")
	}
}

func TestTraySelectNode(t *testing.T) {
	var group, node string
	menu := BuildTrayMenu(TraySnapshot{
		Groups: []TrayGroup{{Name: "PROXY", Now: "n1", Nodes: []string{"n1", "n2"}}},
	}, TrayActions{SelectNode: func(g, n string) {
		group, node = g, n
	}})
	item := menu.ItemByID("PROXY-n2")
	if item == nil || item.Click == nil {
		t.Fatal("missing PROXY-n2")
	}
	item.Click(item, nil)
	if group != "PROXY" || node != "n2" {
		t.Fatalf("tray select %s %s", group, node)
	}
}

func TestTrayInlineModesAndHiddenProxies(t *testing.T) {
	menu := BuildTrayMenu(TraySnapshot{Mode: "global", InlineModes: true, ProxyMenu: "disable"}, TrayActions{})
	top := topLabels(menu.Items())
	for _, label := range top {
		if label == "代理" || strings.HasPrefix(label, "出站模式") {
			t.Fatalf("top %v", top)
		}
	}
	joined := strings.Join(top, "|")
	if !strings.Contains(joined, "全局模式") || !strings.Contains(joined, "规则模式") {
		t.Fatalf("inline %v", top)
	}
}

func topLabels(items []*mygo.MenuItem) []string {
	var out []string
	for _, it := range items {
		if it == nil || it.Label == "" || it.Type == mygo.MenuItemSeparator {
			continue
		}
		out = append(out, it.Label)
	}
	return out
}
