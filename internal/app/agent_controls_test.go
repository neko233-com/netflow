package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

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
