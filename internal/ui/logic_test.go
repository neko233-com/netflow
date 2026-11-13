package ui

import (
	"strings"
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

func TestClassifyDelayAndSignalUseDifferentScales(t *testing.T) {
	if ClassifyDelay(180, 0) != DelayLow || DelayTone(180, 0) != ToneSuccess {
		t.Fatal("chip low")
	}
	if ClassifyDelay(260, 0) != DelayMid || DelayTone(260, 0) != TonePrimary {
		t.Fatal("chip mid")
	}
	if ClassifyDelay(450, 0) != DelayHigh || DelayTone(450, 0) != ToneWarning {
		t.Fatal("chip high")
	}
	if ClassifySignal(180) != SignalExcellent || SignalTone(180) != ToneSuccess {
		t.Fatal("signal excellent")
	}
	if ClassifySignal(220) != SignalGood || SignalTone(220) != ToneInfo {
		t.Fatal("signal good")
	}
	if ClassifySignal(350) != SignalMedium || SignalTone(350) != ToneWarning {
		t.Fatal("signal medium")
	}
	if ClassifySignal(800) != SignalHigh || SignalTone(800) != ToneError {
		t.Fatal("signal high")
	}
	if DelayText(DelayTesting, 0) != "testing" || DelayText(0, 0) != "Timeout" || DelayText(1000000, 0) != "Error" || DelayText(-1, 0) != "-" {
		t.Fatalf("texts %s %s %s %s", DelayText(DelayTesting, 0), DelayText(0, 0), DelayText(1000000, 0), DelayText(-1, 0))
	}
	if SignalLabel(DelayTesting) != "测试中" || SignalBars(80) != 4 || SignalBars(-1) != 0 {
		t.Fatal("signal label")
	}
}

func TestUptimeAndTraffic(t *testing.T) {
	if FormatUptime(time.Hour+2*time.Minute+3*time.Second) != "1:02:03" {
		t.Fatal(FormatUptime(time.Hour + 2*time.Minute + 3*time.Second))
	}
	if FormatUptime(3*time.Second) != "0:00:03" {
		t.Fatal(FormatUptime(3 * time.Second))
	}
	if FormatSpeed(1536) != "1.50 KB/s" {
		t.Fatal(FormatSpeed(1536))
	}
	if !strings.Contains(FormatTraffic(12*1024*1024), "MB") {
		t.Fatal(FormatTraffic(12 * 1024 * 1024))
	}
}

func TestProxyColumnsAndLayout(t *testing.T) {
	if !WideLayout(940) || WideLayout(899) || !WideLayout(900) {
		t.Fatal("breakpoint")
	}
	if ProxyColumns(500, 6) != 1 || ProxyColumns(600, 6) != 2 || ProxyColumns(1100, 0) != 3 || ProxyColumns(1500, 6) != 4 || ProxyColumns(2000, 6) != 5 {
		t.Fatal("auto columns")
	}
	if ProxyColumns(2000, 1) != 1 || ProxyColumns(100, 3) != 3 {
		t.Fatal("fixed columns")
	}
	if ProfileColumns(740) != 2 || ProfileColumns(200) != 1 {
		t.Fatalf("profile cols %d %d", ProfileColumns(740), ProfileColumns(200))
	}
}

func TestFilterAndSort(t *testing.T) {
	nodes := []ProxyNode{
		{Name: "HK-A", Type: "ss", Delay: 120},
		{Name: "HK-B", Type: "vmess", Delay: 480},
		{Name: "US", Type: "ss", Delay: -1},
		{Name: "Slow", Type: "ss", Delay: 0},
		{Name: "Bad", Type: "trojan", Delay: 1000000},
	}
	got := FilterNodes(nodes, "delay<200", SearchOpts{}, 0)
	// "<" is <=, and a timeout of 0 is a measurement, so HK-A (120) and Slow (0) match.
	if len(got) != 2 || got[0].Name != "HK-A" || got[1].Name != "Slow" {
		t.Fatalf("delay<200 %+v", names(got))
	}
	got = FilterNodes(nodes, "type=ss", SearchOpts{}, 0)
	// Type match is a substring, so vmess contains "ss".
	if len(got) != 4 {
		t.Fatalf("type=ss %+v", names(got))
	}
	got = FilterNodes(nodes, "type=trojan", SearchOpts{}, 0)
	if len(got) != 1 || got[0].Name != "Bad" {
		t.Fatalf("type=trojan %+v", names(got))
	}
	got = FilterNodes(nodes, "hk", SearchOpts{}, 0)
	if len(got) != 2 {
		t.Fatalf("name %+v", got)
	}
	got = FilterNodes(nodes, "[", SearchOpts{Regex: true}, 0)
	if len(got) != 0 {
		t.Fatal("bad regex should match nothing")
	}
	sorted := SortNodes(nodes, 1, 10000)
	if sorted[0].Name != "HK-A" || sorted[len(sorted)-1].Delay != -1 {
		t.Fatalf("sort %+v", names(sorted))
	}
	if NextSort(2) != 0 || SortLabel(1) != "按延迟排序" {
		t.Fatal("sort cycle")
	}
	now := time.Now()
	if Debounced(now, now, FilterDebounce) || !Debounced(now.Add(FilterDebounce), now, FilterDebounce) {
		t.Fatal("debounce")
	}
}

func TestURLPortsChainAndEmpty(t *testing.T) {
	if ValidSubscriptionURL("ftp://x") || !ValidSubscriptionURL("https://example.com/a") {
		t.Fatal("url")
	}
	if URLHost("not a url") != "local" || URLHost("https://example.com/a") != "example.com" {
		t.Fatal("host")
	}
	if !FrequentUpdate(60) || FrequentUpdate(1440) || FrequentUpdate(0) {
		t.Fatal("interval")
	}
	if ValidatePorts(PortSet{Mixed: 7897, Socks: 7897, SocksOn: true}) == "" {
		t.Fatal("duplicate should fail")
	}
	if ValidatePorts(PortSet{Mixed: 7897, Socks: 7898, SocksOn: true}) != "" {
		t.Fatal("distinct ports")
	}
	if ValidatePorts(PortSet{Mixed: 0}) == "" {
		t.Fatal("zero port")
	}
	ok, msg := ChainConnectEnabled(1, false, false)
	if ok || msg == "" {
		t.Fatal("chain minimum")
	}
	if r := ResolveProxyList(ProxyListInput{Mode: "direct", GroupCount: 3}); r != EmptyDirect {
		t.Fatal(r)
	}
	if r := ResolveProxyList(ProxyListInput{Mode: "rule"}); r != EmptyNoSubs {
		t.Fatal(r)
	}
	if r := ResolveProxyList(ProxyListInput{Mode: "rule", SubscriptionCnt: 1, HasCurrent: true, CoreRunning: true}); r != EmptyNoInfo {
		t.Fatal(r)
	}
	if r := ResolveProxyList(ProxyListInput{Mode: "rule", SubscriptionCnt: 1, HasCurrent: true, CoreRunning: false}); r != EmptyCore {
		t.Fatal(r)
	}
	if FinishTest("testing", true) == "testing" {
		t.Fatal("failed test stayed testing")
	}
	if !GroupSelectEnabled("rule") || GroupSelectEnabled("direct") || NodeSelectEnabled("direct") || !DelayTestEnabled("rule", true) || DelayTestEnabled("direct", true) {
		t.Fatal("direct disables")
	}
}

func TestPaletteTokens(t *testing.T) {
	light := PaletteFor(false)
	dark := PaletteFor(true)
	if light.Primary != mygoui.Hex("#007AFF") || dark.Primary != mygoui.Hex("#0A84FF") {
		t.Fatalf("primary %v %v", light.Primary, dark.Primary)
	}
	if light.Paper != mygoui.Hex("#F5F5F5") || dark.Paper != mygoui.Hex("#2E303D") {
		t.Fatal("paper")
	}
	if light.Content != mygoui.Hex("#ECECEC") || dark.Content != mygoui.Hex("#1E1F27") {
		t.Fatal("content")
	}
	if light.Card != mygoui.Hex("#FFFFFF") || dark.Card != mygoui.Hex("#282A36") {
		t.Fatal("card")
	}
	if light.Node != mygoui.Hex("#FFFFFF") || dark.Node != mygoui.Hex("#24252F") {
		t.Fatal("node")
	}
	if light.Divider.A == 255 || dark.Divider.A == 255 {
		t.Fatal("divider should be translucent")
	}
	if !strings.Contains(FontStack, "Microsoft YaHei UI") || !strings.Contains(FontStack, "-apple-system") {
		t.Fatal(FontStack)
	}
	th := light.Theme()
	if th.FontSize != 14 || th.Radius != 8 || th.ScrollbarWidth != 8 || th.Dark {
		t.Fatalf("metrics %+v", th)
	}
	if LanguageName("zh") != "简体中文" || LanguageID("简体中文") != "zh" {
		t.Fatal("language endonym")
	}
	for _, n := range Languages() {
		if strings.Contains(n.Name, "语言") {
			t.Fatalf("endonym looks translated: %s", n.Name)
		}
	}
}

func names(nodes []ProxyNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Name
	}
	return out
}
