package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/clashlog"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/query"
	"github.com/neko233-com/netflow/internal/rules"
)

func TestConnectionsTableAndClose(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/connections")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("下载量: 0.00B") || !tt.HasText("上传量: 0.00B") {
		t.Fatalf("header traffic %q", tt.Texts())
	}
	if tt.HasText("0.00 B") {
		t.Fatal("empty header used the spaced cell format")
	}
	if !tt.HasText("空空如也") {
		t.Fatalf("empty connections missing 空空如也: %q", tt.Texts())
	}
	if _, ok := tt.Find("conn-columns"); ok {
		t.Fatal("empty table showed the column icon")
	}
	if tt.HasText("默认") {
		t.Fatal("table layout showed the list sort menu")
	}

	now := time.Date(2026, 4, 21, 13, 0, 0, 0, time.UTC)
	m.Conns.Active = []conn.Item{
		{ID: "a", Host: "www.google.com", DestinationPort: "443", Download: 1024, DownloadSpeed: 1536, Rule: "DomainSuffix", RulePayload: "google.com", Chains: []string{"HK", "Proxy"}, Process: "Safari", Network: "tcp", Type: "HTTPS", Start: now},
		{ID: "b", DestinationIP: "1.1.1.1", DestinationPort: "53", Start: now},
	}
	m.Conns.Closed = []conn.Item{{ID: "c", Host: "old.example", DestinationPort: "80"}}
	var closed []string
	var all int
	m.Hooks.CloseConnection = func(id string) error {
		closed = append(closed, id)
		return nil
	}
	m.Hooks.CloseAllConnections = func() error {
		all++
		return nil
	}
	tt = renderModel(m, WindowWidth, 900, false)
	for _, title := range []string{"主机", "下载量", "上传量", "下载速度", "上传速度", "链路", "规则", "进程", "连接时间", "源地址", "目标地址", "类型", "活跃 2", "已关闭 1", "关闭全部", "1.00 KB", "0.00 B/s"} {
		if !tt.HasText(title) {
			t.Errorf("table missing %q", title)
		}
	}
	if tt.HasText("1.00KB") {
		t.Fatal("cell traffic dropped the space")
	}
	cols, okCols := tt.Find("conn-columns")
	search, okSearch := tt.Find("conn-search")
	matchCase, okCase := tt.Find("conn-case")
	if !okCols || !okSearch || !okCase || cols.X <= search.X || matchCase.X <= search.X || matchCase.X >= cols.X || !overlapsY(cols.Y, cols.H, search.Y, search.H) {
		t.Fatalf("column icon %v search %v case %v", cols, search, matchCase)
	}
	if err := tt.Click("col-host"); err != nil {
		t.Fatal(err)
	}
	if m.Conns.SortDir != 1 || !tt.HasText("▲") {
		t.Fatalf("sort %d texts %v", m.Conns.SortDir, tt.HasText("▲"))
	}
	if err := tt.Click("conn-a"); err != nil {
		t.Fatal(err)
	}
	if m.Conns.Detail == nil || m.Conns.Detail.ID != "a" || !tt.HasText("关闭连接") {
		t.Fatal("detail")
	}
	if err := tt.Click("conn-b"); err != nil {
		t.Fatal(err)
	}
	if m.Conns.Detail.ID != "a" {
		t.Fatal("open detail was replaced")
	}
	if err := tt.Click("close-all"); err != nil {
		t.Fatal(err)
	}
	if all != 1 || len(m.Conns.Active) != 0 {
		t.Fatalf("close all %d active %d", all, len(m.Conns.Active))
	}
	m.Hooks.CloseAllConnections = func() error { return errors.New("nope") }
	m.Conns.Active = []conn.Item{{ID: "a", Host: "keep"}}
	m.Notice = ""
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("close-all"); err != nil {
		t.Fatal(err)
	}
	if len(m.Conns.Active) != 1 || m.Notice != "" {
		t.Fatalf("failed close all active %d notice %q", len(m.Conns.Active), m.Notice)
	}

	m.Conns.Layout = "list"
	m.Conns.Tab = "active"
	m.Conns.Active = []conn.Item{{ID: "a", Host: "www.google.com", DestinationPort: "443", DownloadSpeed: 1536, Network: "tcp"}}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("默认") || !tt.HasText("0.00 B/s / 1.50 KB/s") {
		t.Fatalf("list sort or speed tag: %q", tt.Texts())
	}
	if err := tt.Click("conn-close-a"); err != nil {
		t.Fatal(err)
	}
	if len(closed) != 1 || closed[0] != "a" || len(m.Conns.Active) != 0 {
		t.Fatalf("close one %+v active %d", closed, len(m.Conns.Active))
	}

	cleared := 0
	m.Hooks.ClearClosed = func() { cleared++ }
	m.Conns.Tab = "closed"
	m.Conns.Closed = []conn.Item{{ID: "c", Host: "old.example", DestinationPort: "80"}}
	m.Conns.Layout = "table"
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("clear-closed"); err != nil {
		t.Fatal(err)
	}
	if cleared != 1 || len(m.Conns.Closed) != 0 || all != 1 {
		t.Fatalf("fab cleared %d closed %d closeAll %d", cleared, len(m.Conns.Closed), all)
	}
}

func TestRulesPageAndUpdateAll(t *testing.T) {
	m := NewModel(demoHome())
	m.Router.Replace("/rules")
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("空空如也") {
		t.Fatal("empty rules")
	}
	if _, ok := tt.Find("rule-providers"); ok {
		t.Fatal("empty rules should hide the provider icon")
	}
	m.Rules.Loaded = false
	m.Rules.Items = []rules.Item{
		{Type: "DomainSuffix", Payload: "google.com", Proxy: "Proxy"},
		{Type: "Domain", Payload: "ads.example.com", Proxy: "REJECT"},
		{Type: "Match", Payload: "", Proxy: "DIRECT"},
	}
	m.Rules.Providers = []rules.Provider{{Name: "b", Count: 2, Vehicle: "HTTP", Behavior: "domain", UpdatedAt: "3 小时前"}, {Name: "a", Count: 1, Vehicle: "File", Behavior: "classical"}}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	providers, okProviders := tt.Find("rule-providers")
	if !okProviders || providers.Y > 58 || providers.X < sidebarExpandedWidth {
		t.Fatalf("provider icon should sit in the page header, got %v", providers)
	}
	if !tt.HasText("1") || !tt.HasText("google.com") || !tt.HasText("REJECT") || !tt.HasText("DIRECT") || !tt.HasText("Proxy") {
		t.Fatalf("rules texts %q", tt.Texts())
	}
	m.Rules.Query.Text = "google"
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("1") || tt.HasText("2") && tt.HasText("ads.example.com") {
		t.Fatal("search renumbered or kept a non-payload match")
	}
	if tt.HasText("ads.example.com") {
		t.Fatal("payload search kept ads")
	}
	m.Rules.Query.Text = ""
	m.Rules.ScrollTop = 120
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("rules-top"); err != nil {
		t.Fatal(err)
	}
	if m.Rules.ScrollTop != 0 {
		t.Fatal("scroll top")
	}
	m.Rules.Open = true
	m.Hooks.UpdateRuleProvider = func(name string) error {
		if name == "b" {
			return errors.New("boom")
		}
		return nil
	}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("rules-update-all"); err != nil {
		t.Fatal(err)
	}
	if m.Notice == "" || !strings.Contains(m.Notice, "更新失败") || strings.Contains(m.Notice, "均已更新") || !strings.Contains(m.Notice, "b") {
		t.Fatalf("update all notice %q", m.Notice)
	}
}

func TestLogsPageCaseAndLevels(t *testing.T) {
	if n := len(clashlog.Levels()); n != 5 {
		t.Fatalf("levels %d", n)
	}
	m := NewModel(demoHome())
	m.Router.Replace("/logs")
	when := time.Date(2026, 4, 21, 13, 5, 22, 0, time.UTC)
	m.Logs.Lines = []clashlog.Line{
		{Time: when, Level: "info", Payload: "Google"},
		{Time: when.Add(time.Second), Level: "warning", Payload: "slow"},
		{Time: when.Add(2 * time.Second), Level: "error", Payload: "boom"},
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	for _, label := range []string{"ALL", "清除", "04-21 13:05:22", "INFO", "WARNING", "ERROR"} {
		if !tt.HasText(label) {
			t.Errorf("logs missing %q", label)
		}
	}
	pause, okPause := tt.Find("log-pause")
	order, okOrder := tt.Find("log-order")
	logSearch, okLogSearch := tt.Find("logs-search")
	logCase, okLogCase := tt.Find("logs-case")
	if !okPause || !okOrder || pause.Y > 58 || order.X <= pause.X || pause.X < sidebarExpandedWidth {
		t.Fatalf("log icons pause %v order %v", pause, order)
	}
	if !okLogSearch || !okLogCase || logCase.X <= logSearch.X || !overlapsY(logCase.Y, logCase.H, logSearch.Y, logSearch.H) {
		t.Fatalf("log search icons search %v case %v", logSearch, logCase)
	}
	if tt.HasText("SILENT") {
		t.Fatal("log menu includes SILENT")
	}
	m.Logs.Query = query.Options{Text: "Google", MatchCase: true}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("Google") || tt.HasText("slow") {
		t.Fatal("case-sensitive uppercase query missed Google")
	}
	m.Logs.Query.Text = "google"
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("空空如也") || tt.HasText("Google") {
		t.Fatal("case-sensitive lowercase query matched Google")
	}
	m.Logs.Query.Text = ""
	m.Logs.Level = "warn"
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("slow") || tt.HasText("Google") || tt.HasText("boom") {
		t.Fatal("warn filter")
	}
	m.Logs.Level = "all"
	paused := false
	m.Hooks.SetLogPaused = func(on bool) { paused = on }
	cleared := false
	m.Hooks.ClearLogs = func() { cleared = true }
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("log-pause"); err != nil {
		t.Fatal(err)
	}
	if !paused || !m.Logs.Paused {
		t.Fatal("pause")
	}
	if _, ok := tt.Find("log-pause"); !ok {
		t.Fatal("pause icon disappeared")
	}
	if err := tt.Click("log-order"); err != nil {
		t.Fatal(err)
	}
	if !m.Logs.Desc {
		t.Fatal("order")
	}
	if err := tt.Click("log-clear"); err != nil {
		t.Fatal(err)
	}
	if !cleared || len(m.Logs.Lines) != 0 || !tt.HasText("空空如也") {
		t.Fatal("clear")
	}
}
