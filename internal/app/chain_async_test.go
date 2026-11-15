package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/validation"
)

type controlledChainReload struct {
	coreEngine
	entered, release, canceled chan struct{}
	cancelOnce                 sync.Once
	calls                      atomic.Int32
	failRestore                bool
	failAfterRelease           error
	restoreFailure             error
}

func (e *controlledChainReload) ProviderMembers(name string) ([]core.ProxyNode, error) {
	return e.coreEngine.(interface {
		ProviderMembers(string) ([]core.ProxyNode, error)
	}).ProviderMembers(name)
}

func (e *controlledChainReload) Reload() error {
	call := e.calls.Add(1)
	if call == 1 {
		close(e.entered)
		select {
		case <-e.canceled:
			return context.Canceled
		case <-e.release:
		}
		if e.failAfterRelease != nil {
			return e.failAfterRelease
		}
	}
	if call == 2 && e.failRestore {
		if e.restoreFailure != nil {
			return e.restoreFailure
		}
		return errors.New("injected rollback failure")
	}
	return e.coreEngine.Reload()
}

func (e *controlledChainReload) CancelActiveApply(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	e.cancelOnce.Do(func() { close(e.canceled) })
	return true, nil
}

func TestGUIChainTransactionsAreCancelableAndResponsive(t *testing.T) {
	for _, scenario := range []string{"connect-cancel", "connect-success", "connect-restore-fails", "disconnect-cancel", "disconnect-success", "disconnect-restore-fails", "agent-connect-cancel", "agent-disconnect-cancel", "headless-agent-connect-cancel", "headless-agent-disconnect-cancel", "headless-agent-connect-quit", "headless-agent-disconnect-quit", "agent-connect-context", "agent-disconnect-context", "headless-agent-connect-context", "headless-agent-disconnect-context"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
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
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			underlying := a.core
			defer underlying.Stop()
			nodes := []ui.ProxyNode{{Name: "entry", Provider: "source", SourceGroup: "TARGET"}, {Name: "exit", Provider: "source", SourceGroup: "TARGET"}}
			disconnect := strings.Contains(scenario, "disconnect-")
			agentCall := strings.HasPrefix(scenario, "agent-") || strings.HasPrefix(scenario, "headless-agent-")
			contextCancel := strings.HasSuffix(scenario, "-context")
			var proposal agent.ChainPreview
			if disconnect {
				draft, err := a.prepareChain("TARGET", nodes)
				if err != nil {
					t.Fatal(err)
				}
				checked, err := validateConfigurations(context.Background(), dir, []validation.Config{{Body: draft.composed}})
				if err != nil {
					t.Fatal(err)
				}
				if err := a.finishChain(draft, checked); err != nil {
					t.Fatal(err)
				}
			} else if agentCall {
				var err error
				proposal, err = a.agentChainPreview(agent.ChainPreviewArgs{Target: "TARGET", Hops: []agent.ChainHop{{Name: "entry", Provider: "source", Group: "TARGET"}, {Name: "exit", Provider: "source", Group: "TARGET"}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			engine := &controlledChainReload{coreEngine: underlying, entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{}), failRestore: scenario == "connect-restore-fails" || scenario == "disconnect-restore-fails"}
			a.core = engine
			d := newSerialDispatcher()
			a.dispatch = d.call
			a.headless = strings.HasPrefix(scenario, "headless-agent-")
			defer d.close()
			result := make(chan error, 1)
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			if agentCall {
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
				client := agent.Client{Dir: dir, Timeout: 20 * time.Second}
				go func() {
					if disconnect {
						result <- client.Call(requestCtx, "chain-disconnect", nil, nil)
					} else {
						result <- client.Call(requestCtx, "chain-apply", agent.ApplyArgs{ProposalID: proposal.ProposalID}, nil)
					}
				}()
			} else if disconnect {
				d.call(func() { a.disconnectChainAsync(func(err error) { result <- err }) })
			} else {
				d.call(func() { a.connectChainAsync("TARGET", nodes, func(err error) { result <- err }) })
			}
			select {
			case <-engine.entered:
			case err := <-result:
				t.Fatalf("operation ended before reload: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("reload did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			gated := make(chan struct{})
			go a.runOnMain(func() { close(gated) })
			select {
			case <-gated:
				t.Fatal("mutation escaped barrier")
			case <-time.After(50 * time.Millisecond):
			}
			success := scenario == "connect-success" || scenario == "disconnect-success"
			if success {
				close(engine.release)
			} else if scenario == "headless-agent-connect-quit" || scenario == "headless-agent-disconnect-quit" {
				d.call(func() { a.guiOperation.quit = true; a.cancelGUIConfigOperation(a.guiOperation) })
			} else if contextCancel {
				cancelRequest()
			} else if agentCall {
				client := agent.Client{Dir: dir, Timeout: 5 * time.Second}
				var response agent.CancelApplyResult
				if err := client.Call(context.Background(), "cancel-apply", nil, &response); err != nil || !response.Accepted {
					t.Fatalf("cancel: %+v %v", response, err)
				}
			} else {
				d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("transaction did not finish")
			}
			if success != (err == nil) {
				t.Fatalf("unexpected result: %v", err)
			}
			if contextCancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("request cancellation was not reported: %v", err)
			}
			select {
			case <-gated:
			case <-time.After(time.Second):
				t.Fatal("queued mutation did not resume")
			}
			active := a.chain.Load()
			if scenario == "connect-restore-fails" || scenario == "disconnect-restore-fails" {
				if active == nil || a.model.Chain.Warning == "" {
					t.Fatal("failed rollback lost recovery marker")
				}
			} else if (active != nil) != (disconnect != success) {
				t.Fatalf("chain state after %s: %+v", scenario, active)
			}
			if scenario != "connect-restore-fails" && scenario != "disconnect-restore-fails" {
				group, groupErr := underlying.Group("TARGET")
				if groupErr != nil {
					t.Fatal(groupErr)
				}
				if active == nil && group.Now != "DIRECT" {
					t.Fatalf("original selection not restored: %+v", group)
				}
				if active != nil && group.Now != active.Exit {
					t.Fatalf("chain not restored: %+v", group)
				}
			}
		})
	}
}
