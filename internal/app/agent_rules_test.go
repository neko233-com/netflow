package app

import (
	"errors"
	"fmt"
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
	port := freePort(t)
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
	busyProposal, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	a.tunBusy = true
	if _, err := a.agentPreview(change); err == nil {
		t.Fatal("preview accepted an ongoing TUN transition")
	}
	if _, err := a.agentApply(busyProposal.ProposalID); err == nil {
		t.Fatal("apply accepted an ongoing TUN transition")
	}
	a.tunBusy = false
	changedNetwork, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	a.settings.TUN = true
	if _, err := a.agentApply(changedNetwork.ProposalID); err == nil {
		t.Fatal("apply accepted a proposal after TUN settings changed")
	}
	a.settings.TUN = false
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
	// A different program can change the managed rules file even while this
	// process holds the configuration lock. Never overwrite that edit.
	conflicting, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "agent-rules.json")
	previousDisk, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	external := []byte("{\"revision\":99,\"global\":{},\"future_field\":true}\n")
	if err := os.WriteFile(rulesPath, external, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentPreview(change); !errors.Is(err, rewrite.ErrConflict) {
		t.Fatalf("preview accepted external edit: %v", err)
	}
	if _, err := a.agentApply(conflicting.ProposalID); !errors.Is(err, rewrite.ErrConflict) {
		t.Fatalf("apply accepted external edit: %v", err)
	}
	if got, err := os.ReadFile(rulesPath); err != nil || string(got) != string(external) {
		t.Fatalf("external edit lost: %q %v", got, err)
	}
	if err := os.WriteFile(rulesPath, previousDisk, 0600); err != nil {
		t.Fatal(err)
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

	p1, err := a.profiles.ImportLocal("one.yaml", base)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := a.profiles.ImportLocal("two.yaml", base)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UseProfile(p1.UID); err != nil {
		t.Fatal(err)
	}
	profileChange := agent.Change{Scope: "profile", Operation: "set", ProfileID: p2.UID, Layer: rewrite.Layer{Prepend: []string{"DOMAIN,p2.test,DIRECT"}}}
	profileProposal, err := a.agentPreview(profileChange)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.agentApply(profileProposal.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Active {
		t.Fatal("inactive profile reported as active")
	}
	if err := a.UseProfile(p2.UID); err != nil {
		t.Fatal(err)
	}
	rules = a.core.Rules()
	if len(rules) < 3 || rules[0].Payload != "p2.test" || rules[1].Payload != "example.test" {
		t.Fatalf("profile layering: %+v", rules)
	}
	if err := a.UseProfile(p1.UID); err != nil {
		t.Fatal(err)
	}
	rules = a.core.Rules()
	if len(rules) < 2 || rules[0].Payload != "example.test" {
		t.Fatalf("profile override leaked: %+v", rules)
	}
}

func TestExpiredRuntimeRuleRemovedWhenStateFileConflicts(t *testing.T) {
	dir := t.TempDir()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns:\n  enable: false\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", freePort(t)))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	expires := time.Now().Add(2 * time.Second)
	state := a.rewrites.Snapshot()
	state.Connections = []rewrite.Connection{{ID: "test", ProfileID: a.core.ProfileID(), Rule: "DOMAIN,temporary.test,REJECT", ExpiresAt: expires}}
	if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Reload(); err != nil {
		t.Fatal(err)
	}
	if rules := a.core.Rules(); len(rules) < 2 || rules[0].Payload != "temporary.test" {
		t.Fatalf("temporary rule absent: %+v", rules)
	}
	path := filepath.Join(dir, "agent-rules.json")
	external := []byte("{\"revision\":99,\"global\":{},\"future_field\":true}\n")
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(expires.Add(50 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if err := a.expireRules(time.Now()); !errors.Is(err, rewrite.ErrConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	if rules := a.core.Rules(); len(rules) != 1 || rules[0].Payload == "temporary.test" {
		t.Fatalf("expired rule still active: %+v", rules)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(external) {
		t.Fatalf("external edit lost: %q %v", got, err)
	}
	status, err := a.agentStatus()
	if err != nil || status.RewriteWarning == "" {
		t.Fatalf("missing agent warning: %+v %v", status, err)
	}
}
