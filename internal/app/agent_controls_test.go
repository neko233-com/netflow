package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/rules"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type pagingTestEngine struct {
	*switchTestEngine
	items     []conn.Item
	ruleItems []rules.Item
}

func (e *pagingTestEngine) Connections() ([]conn.Item, int64, int64) { return e.items, 0, 0 }
func (e *pagingTestEngine) Rules() []rules.Item                      { return e.ruleItems }

func TestAgentConnectionAndRulePages(t *testing.T) {
	items := make([]conn.Item, 300)
	for i := range items {
		items[i] = conn.Item{ID: fmt.Sprintf("%04d", len(items)-i), Host: "example.invalid"}
	}
	engine := &pagingTestEngine{switchTestEngine: &switchTestEngine{running: true}, items: items}
	dir := t.TempDir()
	rw, err := rewrite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{core: engine, rewrites: rw, profiles: profile.NewStore(dir)}
	status, err := a.agentStatus()
	if err != nil || status.ConnectionsTotal != 300 || !status.ConnectionsTruncated || len(status.Connections) != 100 || status.Connections[0].ID != "0001" {
		t.Fatalf("unexpected status page: %+v %v", status, err)
	}
	page, err := a.agentConnections(agent.ConnectionsArgs{Offset: 100, Limit: 200})
	if err != nil || page.Total != 300 || page.NextOffset != 300 || page.Connections[0].ID != "0101" || items[0].ID != "0300" {
		t.Fatalf("unstable connection page: %+v %v", page, err)
	}
	if _, err := a.agentConnections(agent.ConnectionsArgs{Limit: 501}); err == nil {
		t.Fatal("invalid limit accepted")
	}
	engine.items = []conn.Item{{ID: "1", Host: strings.Repeat("<", maxAgentPageBytes)}}
	status, err = a.agentStatus()
	if err != nil || !status.ConnectionsTruncated || status.ConnectionsWarning == "" || len(status.Connections) != 0 {
		t.Fatalf("oversized connection blocked status: %+v %v", status, err)
	}
	if _, err := a.agentConnections(agent.ConnectionsArgs{}); err == nil {
		t.Fatal("oversized connection accepted")
	}
	engine.ruleItems = []rules.Item{{Type: "DOMAIN", Payload: strings.Repeat("<", 30000), Proxy: "DIRECT"}, {Type: "DOMAIN", Payload: strings.Repeat("<", 30000), Proxy: "DIRECT"}, {Type: "MATCH", Proxy: "DIRECT"}}
	first, err := a.agentRules(agent.RulesArgs{Limit: 3})
	if err != nil || first.Total != 3 || first.NextOffset != 1 {
		t.Fatalf("rule byte bound: %+v %v", first, err)
	}
	second, err := a.agentRules(agent.RulesArgs{Offset: first.NextOffset, Limit: 3})
	if err != nil || second.NextOffset != 3 {
		t.Fatalf("rule continuation: %+v %v", second, err)
	}
}

func TestAgentControlsOperateOnRealCore(t *testing.T) {
	dir := t.TempDir()
	config := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nproxy-groups:\n  - name: TestGroup\n    type: select\n    proxies: [DIRECT, REJECT]\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "source.yaml")
	if err := os.WriteFile(file, config, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if err := a.ImportLocal(file); err != nil {
		t.Fatal(err)
	}
	value, err := a.agentCommand("groups", nil)
	if err != nil {
		t.Fatal(err)
	}
	groups := value.(agent.GroupsResult)
	if len(groups.Groups) != 1 || len(groups.Groups[0].Nodes) != 2 {
		t.Fatalf("groups: %+v", groups)
	}
	value, err = a.agentCommand("rules", json.RawMessage(`{"offset":0,"limit":1}`))
	if err != nil || value.(agent.RulesResult).Total != 1 || len(value.(agent.RulesResult).Rules) != 1 {
		t.Fatalf("rules: %+v %v", value, err)
	}
	if _, err = a.agentCommand("rules", json.RawMessage(`{"limit":501}`)); err == nil {
		t.Fatal("oversized rule page accepted")
	}
	value, err = a.agentCommand("select", json.RawMessage(`{"group":"TestGroup","node":"REJECT"}`))
	if err != nil || !value.(agent.ActionResult).OK {
		t.Fatalf("select: %+v %v", value, err)
	}
	if selected, err := a.core.Selected("TestGroup"); err != nil || selected != "REJECT" {
		t.Fatalf("core choice %s %v", selected, err)
	}
	if err := a.core.Select("TestGroup", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentCommand("groups", nil); err != nil {
		t.Fatal(err)
	}
	if selected, err := a.core.Selected("TestGroup"); err != nil || selected != "DIRECT" {
		t.Fatalf("read-only group listing changed selection: %s %v", selected, err)
	}
	if _, err = a.agentCommand("mode", json.RawMessage(`{"mode":"global"}`)); err != nil || a.core.Status().Mode != "global" {
		t.Fatalf("mode: %v", err)
	}
	if _, err = a.agentCommand("use-profile", json.RawMessage(`{"profile_id":"missing"}`)); err == nil {
		t.Fatal("nonexistent profile accepted")
	}
	value, err = a.agentCommand("close-connection", json.RawMessage(`{"connection_id":"missing"}`))
	if err != nil || value.(agent.CloseResult).Closed {
		t.Fatalf("missing connection: %+v %v", value, err)
	}
	if _, err = a.agentCommand("select", json.RawMessage(`{"group":"TestGroup","node":"DIRECT"} {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
