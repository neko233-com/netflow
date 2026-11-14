package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/validation"
)

type chainFailReloadEngine struct {
	coreEngine
	failures int
}

func (e *chainFailReloadEngine) Reload() error {
	if e.failures > 0 {
		e.failures--
		return errors.New("injected reload failure")
	}
	return e.coreEngine.Reload()
}

func TestChainTransactionAndAgentPreview(t *testing.T) {
	dir := t.TempDir()
	base := fmt.Sprintf(`mixed-port: %d
mode: rule
log-level: error
dns: {enable: false}
tun: {enable: false}
proxy-providers:
  source:
    type: inline
    payload:
      - {name: entry, type: socks5, server: 127.0.0.1, port: 9}
      - {name: exit, type: socks5, server: 127.0.0.1, port: 10}
proxy-groups:
  - {name: TARGET, type: select, proxies: [DIRECT], use: [source]}
rules: ['MATCH,TARGET']
`, freePort(t))
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core: %s", a.model.Home.Error)
	}
	nodes := []ui.ProxyNode{{Name: "entry", Provider: "source", SourceGroup: "TARGET"}, {Name: "exit", Provider: "source", SourceGroup: "TARGET"}}
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,example.test,REJECT"}}}
	stale, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := a.prepareChain("TARGET", nodes)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := validateConfigurations(context.Background(), dir, []validation.Config{{Body: draft.composed}})
	if err != nil {
		t.Fatal(err)
	}
	// A changed disk configuration must invalidate validation, even if the
	// running kernel has not reloaded that external change yet.
	if err := os.WriteFile(path, []byte(base+"# changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.finishChain(draft, checked); err == nil {
		t.Fatal("external source change accepted")
	}
	if a.chain.Load() != nil {
		t.Fatal("failed preflight activated chain")
	}
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.finishChain(draft, checked); err != nil {
		t.Fatal(err)
	}
	if a.chain.Load() == nil {
		t.Fatal("chain not activated")
	}
	if _, err := a.agentApply(stale.ProposalID); err == nil {
		t.Fatal("rule preview survived chain change")
	}
	if err := a.SetMode("global"); err == nil {
		t.Fatal("mode changed while chain active")
	}
	if err := a.SelectProxy("TARGET", "DIRECT"); err == nil {
		t.Fatal("target selection bypassed chain")
	}
	next, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.agentApply(next.ProposalID); err != nil {
		t.Fatal(err)
	}
	group, err := a.core.Group("TARGET")
	if err != nil || group.Now != draft.active.Exit || len(group.Nodes) != 1 {
		t.Fatalf("chain lost after rule reload: %+v %v", group, err)
	}
	if err := a.disconnectChain(); err != nil {
		t.Fatal(err)
	}
	if a.chain.Load() != nil {
		t.Fatal("chain state remains")
	}
	group, err = a.core.Group("TARGET")
	if err != nil || group.Now != "DIRECT" {
		t.Fatalf("selector not restored: %+v %v", group, err)
	}
	request := agent.ChainPreviewArgs{Target: "TARGET", Hops: []agent.ChainHop{{Name: "entry", Provider: "source", Group: "TARGET"}, {Name: "exit", Provider: "source", Group: "TARGET"}}}
	proposal, err := a.agentChainPreview(request)
	if err != nil {
		t.Fatal(err)
	}
	if a.agentChainStatus().Configured {
		t.Fatal("preview changed routing")
	}
	if err := os.WriteFile(path, []byte(base+"# changed again\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentChainApply(proposal.ProposalID); err == nil {
		t.Fatal("stale chain proposal accepted")
	}
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	proposal, err = a.agentChainPreview(request)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.agentChainApply(proposal.ProposalID)
	if err != nil || !result.Active || !result.Configured {
		t.Fatalf("chain apply: %+v %v", result, err)
	}
	if !a.model.Chain.Connected {
		t.Fatal("agent activation did not update GUI")
	}
	if _, err := a.agentChainApply(proposal.ProposalID); err == nil {
		t.Fatal("chain proposal reused")
	}
	if err := a.disconnectChain(); err != nil {
		t.Fatal(err)
	}
	if a.model.Chain.Connected || a.agentChainStatus().Configured {
		t.Fatal("chain did not disconnect")
	}
	// A failed reload restores the old configuration; if restoration itself
	// fails, preserve a visible recovery marker rather than reporting success.
	underlying := a.core
	for _, failures := range []int{1, 2} {
		draft, err := a.prepareChain("TARGET", nodes)
		if err != nil {
			t.Fatal(err)
		}
		checked, err := validateConfigurations(context.Background(), dir, []validation.Config{{Body: draft.composed}})
		if err != nil {
			t.Fatal(err)
		}
		failing := &chainFailReloadEngine{coreEngine: underlying, failures: failures}
		a.core = failing
		if err := a.finishChain(draft, checked); err == nil {
			t.Fatal("failed chain reload was reported as success")
		}
		if failures == 1 && a.chain.Load() != nil {
			t.Fatal("successful rollback retained chain")
		}
		if failures == 2 {
			if a.chain.Load() == nil || a.model.Chain.Warning == "" {
				t.Fatal("failed rollback was not recoverable or visible")
			}
			if err := a.disconnectChain(); err != nil {
				t.Fatal(err)
			}
		}
		a.core = underlying
	}
	// An externally replaced profile can remove the old group. Disconnect
	// must still clear the session and report that the old choice is gone.
	draft, err = a.prepareChain("TARGET", nodes)
	if err != nil {
		t.Fatal(err)
	}
	checked, err = validateConfigurations(context.Background(), dir, []validation.Config{{Body: draft.composed}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.finishChain(draft, checked); err != nil {
		t.Fatal(err)
	}
	changed := fmt.Sprintf("mixed-port: %d\nmode: rule\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", a.core.Status().MixedPort)
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	disconnectResult, err := a.agentCommand("chain-disconnect", nil)
	if err != nil {
		t.Fatal(err)
	}
	action, ok := disconnectResult.(agent.ActionResult)
	if !ok || !action.OK || len(action.Warnings) == 0 || a.chain.Load() != nil {
		t.Fatalf("missing disconnect warning: %+v", disconnectResult)
	}
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Reload(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != base || strings.Contains(string(raw), "__netflow_chain_") {
		t.Fatal("source config was altered")
	}
}
