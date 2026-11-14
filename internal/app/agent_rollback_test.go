package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestAgentRollbackPreviewAppliesOnlySelectedScope(t *testing.T) {
	dir := t.TempDir()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	apply := func(change agent.Change) agent.ApplyResult {
		t.Helper()
		p, err := a.agentPreview(change)
		if err != nil {
			t.Fatal(err)
		}
		result, err := a.agentApply(p.ProposalID)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := apply(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,first.test,REJECT"}}})
	apply(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,second.test,DIRECT"}}})
	history, err := a.agentRewriteHistory()
	if err != nil || len(history.Entries) < 2 || history.Entries[0].Revision != first.Revision {
		t.Fatalf("missing previous history: %+v %v", history, err)
	}
	preview, err := a.agentRollbackPreview(agent.RollbackArgs{Revision: &first.Revision, Scope: "global"})
	if err != nil || len(preview.Warnings) == 0 || !strings.Contains(strings.Join(preview.RulesAfter, "\n"), "first.test") || !strings.Contains(strings.Join(preview.RulesBefore, "\n"), "second.test") {
		t.Fatalf("incorrect rollback preview: %+v %v", preview, err)
	}
	if a.rewrites.Snapshot().Global.Prepend[0] != "DOMAIN,second.test,DIRECT" {
		t.Fatal("preview changed state")
	}
	if _, err := a.rewrites.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(preview.ProposalID); err == nil {
		t.Fatal("cleared history did not invalidate preview")
	}
	apply(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,first.test,REJECT"}}})
	first = apply(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,second.test,DIRECT"}}})
	prior := first.Revision - 1
	preview, err = a.agentRollbackPreview(agent.RollbackArgs{Revision: &prior, Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(preview.ProposalID); err != nil {
		t.Fatal(err)
	}
	if rules := a.core.Rules(); len(rules) < 2 || rules[0].Payload != "first.test" {
		t.Fatalf("rollback not applied: %+v", rules)
	}
	if err := a.importURLData("https://first.invalid/sub", base, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.importURLData("https://second.invalid/sub", base, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil || len(catalog.Items) != 2 {
		t.Fatal("profiles unavailable", err)
	}
	profileID := catalog.Items[1].UID
	beforeProfile := a.rewrites.Snapshot().Revision
	apply(agent.Change{Scope: "profile", Operation: "set", ProfileID: profileID, Layer: rewrite.Layer{Prepend: []string{"DOMAIN,profile.test,REJECT"}}})
	preview, err = a.agentRollbackPreview(agent.RollbackArgs{Revision: &beforeProfile, Scope: "profile", ProfileID: profileID})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.agentApply(preview.ProposalID)
	if err != nil || result.Active {
		t.Fatalf("inactive profile rollback: %+v %v", result, err)
	}
	state := a.rewrites.Snapshot()
	if _, ok := state.Profiles[profileID]; ok || state.Global.Prepend[0] != "DOMAIN,first.test,REJECT" {
		t.Fatal("rollback changed unrelated scope")
	}
}

type rollbackConnectionEngine struct {
	*switchTestEngine
	items []conn.Item
}

func (e *rollbackConnectionEngine) Connections() ([]conn.Item, int64, int64) { return e.items, 0, 0 }

func TestConnectionRollbackRejectsExpiredOrChangedMatcher(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	base := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	if err := a.importURLData("https://example.invalid/sub", base, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	a.rewrites, err = rewrite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	item := conn.Item{ID: "connection", Network: "tcp", Host: "example.test", SourceIP: "127.0.0.1", DestinationPort: "443"}
	engine := &rollbackConnectionEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir, id: catalog.Current}, items: []conn.Item{item}}
	a.core = engine
	rule, err := connectionRule(item, "REJECT")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute)
	state := a.rewrites.Snapshot()
	state.Connections = []rewrite.Connection{{ID: item.ID, ProfileID: catalog.Current, Rule: rule, ExpiresAt: expires}}
	first, err := a.rewrites.Replace(state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	state = first
	state.Connections = nil
	if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
		t.Fatal(err)
	}
	draft, err := a.prepareAgentRollback(agent.RollbackArgs{Revision: &first.Revision, Scope: "connection", ConnectionID: item.ID})
	if err != nil || len(draft.state.Connections) != 1 || draft.state.Connections[0].Rule != rule || draft.state.Connections[0].ExpiresAt.After(expires) {
		t.Fatalf("invalid connection rollback: %+v %v", draft, err)
	}
	engine.items[0].DestinationPort = "8443"
	if _, err := a.prepareAgentRollback(agent.RollbackArgs{Revision: &first.Revision, Scope: "connection", ConnectionID: item.ID}); err == nil {
		t.Fatal("changed connection accepted")
	}
	engine.items = nil
	if _, err := a.prepareAgentRollback(agent.RollbackArgs{Revision: &first.Revision, Scope: "connection", ConnectionID: item.ID}); err == nil {
		t.Fatal("closed connection accepted")
	}
	engine.items = []conn.Item{item}
	state = a.rewrites.Snapshot()
	state.Connections = []rewrite.Connection{{ID: item.ID, ProfileID: catalog.Current, Rule: rule, ExpiresAt: time.Now().Add(-time.Second)}}
	expired, err := a.rewrites.Replace(state, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	state = expired
	state.Connections = nil
	if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := a.prepareAgentRollback(agent.RollbackArgs{Revision: &expired.Revision, Scope: "connection", ConnectionID: item.ID}); err == nil {
		t.Fatal("expired matcher accepted")
	}
}
