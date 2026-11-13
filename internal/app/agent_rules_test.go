package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestAgentApplyValidatesPersistsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	path := filepath.Join(dir, "config.yaml")
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns:\n  enable: false\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", port))
	if err := os.WriteFile(path, base, 0600); err != nil {
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
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,example.test,REJECT"}}}
	first, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.agentApply(first.ProposalID); err != nil {
		t.Fatal(err)
	}
	rules := a.core.Rules()
	if len(rules) < 2 || rules[0].Proxy != "REJECT" || rules[0].Payload != "example.test" {
		t.Fatalf("rules: %+v", rules)
	}
	if _, err = a.agentApply(stale.ProposalID); err == nil {
		t.Fatal("stale proposal accepted")
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(base) {
		t.Fatal("base config changed")
	}
	invalid := change
	invalid.Layer.Prepend = []string{"DOMAIN,example.test,NOT_A_POLICY"}
	if _, err := a.agentPreview(invalid); err == nil {
		t.Fatal("invalid policy accepted")
	}
	prior := a.rewrites.Snapshot()
	next := change
	next.Layer.Prepend = []string{"DOMAIN,second.test,DIRECT"}
	proposal, err := a.agentPreview(next)
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	a.core.SetTransformer(func(raw []byte, id string) ([]byte, error) {
		if !failed {
			failed = true
			return nil, errors.New("injected failure")
		}
		out, _, err := rewrite.Compose(raw, a.rewrites.Snapshot(), id, time.Now())
		return out, err
	})
	if _, err = a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("injected failure ignored")
	}
	current := a.rewrites.Snapshot()
	if current.Global.Prepend[0] != prior.Global.Prepend[0] {
		t.Fatalf("state not rolled back: %+v", current)
	}
	rules = a.core.Rules()
	if len(rules) < 2 || rules[0].Payload != "example.test" {
		t.Fatalf("core not restored: %+v", rules)
	}
}
