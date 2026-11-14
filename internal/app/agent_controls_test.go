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
	"github.com/neko233-com/netflow/internal/ui"
)

type pagingTestEngine struct {
	*switchTestEngine
	items      []conn.Item
	ruleItems  []rules.Item
	groupItems []core.ProxyNode
}

func (e *pagingTestEngine) Connections() ([]conn.Item, int64, int64) { return e.items, 0, 0 }
func (e *pagingTestEngine) Rules() []rules.Item                      { return e.ruleItems }
func (e *pagingTestEngine) Group(name string) (core.ProxyGroup, error) {
	return core.ProxyGroup{Name: name, Type: "Selector", Now: "node-000", Nodes: e.groupItems}, nil
}

func TestAgentPagesAdvanceAtExactByteLimit(t *testing.T) {
	item := strings.Repeat("x", maxAgentPageBytes-4)
	page, _, next, err := boundedAgentPage([]string{item}, 0, 1, maxAgentPageBytes)
	if err != nil || next != 1 || len(page) != 1 {
		t.Fatalf("generic boundary did not advance: %d %v", next, err)
	}
	if _, _, _, err := boundedAgentPage([]string{item + "x"}, 0, 1, maxAgentPageBytes); err == nil {
		t.Fatal("oversized generic item accepted")
	}
	c := conn.Item{ID: "id"}
	base, _ := json.Marshal(c)
	c.Host = strings.Repeat("x", maxAgentPageBytes-2-len(base))
	connections, err := connectionPage([]conn.Item{c}, agent.ConnectionsArgs{})
	if err != nil || connections.NextOffset != 1 {
		t.Fatalf("connection boundary did not advance: %d %v", connections.NextOffset, err)
	}
	r := agent.Rule{Type: "DOMAIN", Policy: "DIRECT"}
	base, _ = json.Marshal(r)
	engine := &pagingTestEngine{switchTestEngine: &switchTestEngine{running: true}, ruleItems: []rules.Item{{Type: r.Type, Proxy: r.Policy, Payload: strings.Repeat("x", maxAgentPageBytes-2-len(base))}}}
	rulePage, err := (&App{core: engine}).agentRules(agent.RulesArgs{})
	if err != nil || rulePage.NextOffset != 1 {
		t.Fatalf("rule boundary did not advance: %d %v", rulePage.NextOffset, err)
	}
}

func TestAgentProfileAndGroupPages(t *testing.T) {
	dir := t.TempDir()
	config := []byte("mixed-port: 0\nproxy-groups:\n  - name: Test\n    type: select\n    proxies: [DIRECT]\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	engine := &pagingTestEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir}}
	for i := 0; i < 250; i++ {
		engine.groupItems = append(engine.groupItems, core.ProxyNode{Name: fmt.Sprintf("node-%03d", i), Type: "Socks"})
	}
	a := &App{dir: dir, core: engine, model: ui.NewModel(ui.HomeState{}), profiles: profile.NewStore(dir)}
	groups, err := a.agentGroups()
	if err != nil || len(groups.Groups) != 1 || groups.Groups[0].NodesTotal != 250 || !groups.Groups[0].NodesTruncated || len(groups.Groups[0].Nodes) != 100 {
		t.Fatalf("group preview: %+v %v", groups, err)
	}
	nodes, err := a.agentGroupNodes(agent.GroupNodesArgs{Group: "Test", Offset: 100, Limit: 150})
	if err != nil || nodes.Total != 250 || nodes.NextOffset != 250 || nodes.Nodes[0].Name != "node-100" {
		t.Fatalf("group page: %+v %v", nodes, err)
	}
	catalog := profile.File{Current: "p200"}
	for i := 0; i < 250; i++ {
		catalog.Items = append(catalog.Items, profile.CatalogItem{UID: fmt.Sprintf("p%03d", i), Name: "profile"})
	}
	if err := a.profiles.Save(catalog); err != nil {
		t.Fatal(err)
	}
	page, err := a.agentProfilesPage(agent.PageArgs{Offset: 100, Limit: 150})
	if err != nil || page.Total != 250 || page.NextOffset != 250 || page.Profiles[100].ID != "p200" || !page.Profiles[100].Active {
		t.Fatalf("profile page: %+v %v", page, err)
	}
	a.rewrites, err = rewrite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	status, err := a.agentStatus()
	if err != nil || status.ProfilesTotal != 250 || !status.ProfilesTruncated || len(status.Profiles) != 100 {
		t.Fatalf("profile status: %+v %v", status, err)
	}
	engine.groupItems = []core.ProxyNode{{Name: strings.Repeat("<", 15000)}, {Name: strings.Repeat("<", 15000)}, {Name: "last"}}
	first, err := a.agentGroupNodes(agent.GroupNodesArgs{Group: "Test", Limit: 3})
	if err != nil || first.NextOffset != 1 {
		t.Fatalf("group node byte bound: next=%d %v", first.NextOffset, err)
	}
	last, err := a.agentGroupNodes(agent.GroupNodesArgs{Group: "Test", Offset: first.NextOffset, Limit: 3})
	if err != nil || last.NextOffset != 3 {
		t.Fatalf("group node continuation: next=%d %v", last.NextOffset, err)
	}
	catalog.Items = []profile.CatalogItem{{UID: "large", Name: strings.Repeat("<", maxAgentPageBytes)}}
	if err := a.profiles.Save(catalog); err != nil {
		t.Fatal(err)
	}
	status, err = a.agentStatus()
	if err != nil || !status.ProfilesTruncated || status.ProfilesWarning == "" || len(status.Profiles) != 0 {
		t.Fatalf("oversized profile blocked status: %v", err)
	}
}

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
