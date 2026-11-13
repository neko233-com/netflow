package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestVergeProviderImportRunsAndInvalidatesAgentPreview(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	source := t.TempDir()
	for _, dir := range []string{"profiles", "sets"} {
		if err := os.Mkdir(filepath.Join(source, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"profiles.yaml":   "current: p\nitems:\n  - {uid: p, type: local, name: Test, file: p.yaml, option: {merge: m}}\n  - {uid: m, type: merge, file: m.yaml}\n",
		"profiles/p.yaml": fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\ndns: {enable: false}\ntun: {enable: false}\nproxy-groups: [{name: Select, type: select, use: [nodes]}]\nrules: ['RULE-SET,blocked,REJECT', 'MATCH,DIRECT']\n", port),
		"profiles/m.yaml": "proxy-providers:\n  nodes: {type: file, path: ./sets/nodes.yaml, health-check: {enable: false}}\nrule-providers:\n  blocked: {type: file, behavior: domain, format: yaml, path: ./sets/rules.yaml}\n",
		"sets/nodes.yaml": "proxies:\n  - {name: migrated-direct, type: direct}\n",
		"sets/rules.yaml": "payload:\n  - '+.blocked.test'\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parsed, err := migration.ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := parsed.ImportVerge(dir); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core failed: %s", a.model.Home.Error)
	}
	group, err := a.core.Group("Select")
	if err != nil || len(group.Nodes) != 1 || group.Nodes[0].Name != "migrated-direct" {
		t.Fatalf("provider not loaded: %+v %v", group, err)
	}
	if len(a.core.RuleProviders()) != 1 {
		t.Fatalf("rule provider not loaded: %+v", a.core.RuleProviders())
	}
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,example.test,DIRECT"}}}
	proposal, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	managed := catalog.Items[0].Option.VergeProviderPaths["./sets/rules.yaml"]
	if !strings.HasPrefix(managed, "verge-providers/") {
		t.Fatalf("bad managed path: %q", managed)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(managed)), []byte("payload: ['+.changed.test']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("provider edit did not invalidate proposal")
	}
}
