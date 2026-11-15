package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIAgentRuleApplyRemainsResponsiveAndRollsBack(t *testing.T) {
	for _, scenario := range []string{"global-cancel", "profile-cancel", "global-success", "agent-cancel", "quit", "external-rules", "external-options", "external-source-success", "external-source-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var requests atomic.Int32
			var canceledOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					close(entered)
					select {
					case <-r.Context().Done():
						canceledOnce.Do(func() { close(canceled) })
						return
					case <-release:
					}
				}
				_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
			}))
			defer provider.Close()
			defer unblock()
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			store := profile.NewStore(dir)
			item, err := store.ImportLocal("first.yaml", []byte(base))
			if err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			config := filepath.Join(dir, "config.yaml")
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/rules.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(config, []byte(next), 0600); err != nil {
				t.Fatal(err)
			}
			change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,gui-rule.test,REJECT"}}}
			if scenario == "profile-cancel" {
				change.Scope, change.ProfileID = "profile", item.UID
			}
			preview, err := a.agentPreview(change)
			if err != nil {
				t.Fatalf("validated preview: %v", err)
			}
			before := a.rewrites.Snapshot()
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			quitCalled := make(chan struct{})
			if scenario == "quit" {
				a.guiQuit = func() { close(quitCalled) }
			}
			type response struct {
				value agent.ApplyResult
				err   error
			}
			result := make(chan response, 1)
			client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
			if scenario == "agent-cancel" {
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
				go func() {
					var out agent.ApplyResult
					err := client.Call(context.Background(), "apply", agent.ApplyArgs{ProposalID: preview.ProposalID}, &out)
					result <- response{out, err}
				}()
			} else {
				d.call(func() {
					a.agentApplyAsync(preview.ProposalID, func(out agent.ApplyResult, err error) { result <- response{out, err} })
				})
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("rule provider did not begin")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked during rule application")
			}
			gated := make(chan struct{})
			go a.runOnMain(func() { close(gated) })
			select {
			case <-gated:
				t.Fatal("mutation ran before rule transaction finished")
			case <-time.After(100 * time.Millisecond):
			}
			if strings.HasPrefix(scenario, "external-source-") {
				if err := os.WriteFile(config, []byte(next+"# external edit\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "global-success" || scenario == "external-source-success" {
				unblock()
			} else {
				if scenario == "external-rules" {
					if err := os.WriteFile(filepath.Join(dir, "agent-rules.json"), []byte("{\"revision\":99,\"global\":{},\"external\":true}\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "external-options" {
					if err := os.WriteFile(filepath.Join(dir, "kernel-options.json"), []byte("{\"log_level\":\"debug\",\"external\":true}\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "agent-cancel" {
					var response agent.CancelApplyResult
					if err := client.Call(context.Background(), "cancel-apply", nil, &response); err != nil || !response.Accepted {
						t.Fatalf("Agent cancel: %+v %v", response, err)
					}
				} else {
					d.call(func() {
						if scenario == "quit" {
							a.guiOperation.quit = true
						}
						a.cancelGUIConfigOperation(a.guiOperation)
					})
				}
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("rule provider was not canceled")
				}
			}
			var out response
			select {
			case out = <-result:
			case <-time.After(15 * time.Second):
				t.Fatal("rule transaction did not finish")
			}
			if scenario == "global-success" && (out.err != nil || !out.value.Active) {
				t.Fatalf("rule application: %+v %v", out.value, out.err)
			}
			if scenario != "global-success" && out.err == nil {
				t.Fatal("canceled rule application reported success")
			}
			if scenario == "quit" {
				select {
				case <-quitCalled:
				case <-time.After(5 * time.Second):
					t.Fatal("GUI quit was not requested")
				}
				select {
				case <-gated:
					t.Fatal("queued callback ran before the GUI event loop exited")
				case <-time.After(100 * time.Millisecond):
				}
				d.call(func() { a.releaseGUIBarrierAfterExit() })
			}
			select {
			case <-gated:
			case <-time.After(5 * time.Second):
				t.Fatal("queued callback did not resume")
			}
			if scenario == "external-rules" {
				data, readErr := os.ReadFile(filepath.Join(dir, "agent-rules.json"))
				if readErr != nil || !strings.Contains(string(data), "external") || !strings.Contains(out.err.Error(), "restore previous rules") {
					t.Fatalf("external rules conflict was not preserved: %s %v", data, out.err)
				}
				return
			}
			if scenario == "external-options" {
				data, readErr := os.ReadFile(filepath.Join(dir, "kernel-options.json"))
				if readErr != nil || !strings.Contains(string(data), "external") || !reflect.DeepEqual(a.rewrites.Snapshot().Global, before.Global) || !strings.Contains(out.err.Error(), "runtime may retain") {
					t.Fatalf("external options conflict was not preserved or disclosed: %s %v", data, out.err)
				}
				if requests.Load() != 1 {
					t.Fatal("rollback reloaded with unvalidated external options")
				}
				return
			}
			if strings.HasPrefix(scenario, "external-source-") {
				data, readErr := os.ReadFile(config)
				after := a.rewrites.Snapshot()
				if readErr != nil || string(data) != next+"# external edit\n" || !reflect.DeepEqual(after.Global, before.Global) || !strings.Contains(out.err.Error(), "runtime may retain") {
					t.Fatalf("external source conflict was not preserved or disclosed: %v %v", readErr, out.err)
				}
				if requests.Load() != 1 {
					t.Fatal("rollback reloaded an unvalidated external configuration")
				}
				return
			}
			after := a.rewrites.Snapshot()
			if a.agentApplyGuard.Load() != nil {
				t.Fatal("rule application guard remained installed")
			}
			if scenario == "global-success" {
				if len(after.Global.Prepend) != 1 || after.Global.Prepend[0] != "DOMAIN,gui-rule.test,REJECT" {
					t.Fatalf("rules were not committed: %+v", after.Global)
				}
			} else if !reflect.DeepEqual(after.Global, before.Global) || !reflect.DeepEqual(after.Profiles, before.Profiles) || len(after.Connections) != len(before.Connections) {
				t.Fatal("canceled rules were not restored")
			}
			data, err := os.ReadFile(config)
			if err != nil || string(data) != next {
				t.Fatal("rule application overwrote the subscription")
			}
		})
	}
}

type asyncConnectionEngine struct {
	*switchTestEngine
	items                                  []conn.Item
	started, release, canceled             chan struct{}
	startedOnce, releaseOnce, canceledOnce sync.Once
	reloads, closed                        atomic.Int32
}

func (e *asyncConnectionEngine) Status() core.Status {
	return core.Status{Running: true, Mode: "rule", ConfigDir: e.dir}
}
func (e *asyncConnectionEngine) Connections() ([]conn.Item, int64, int64) { return e.items, 0, 0 }
func (e *asyncConnectionEngine) CloseExistingConnection(id string) (bool, error) {
	if id == "connection" {
		e.closed.Add(1)
		return true, nil
	}
	return false, nil
}
func (e *asyncConnectionEngine) Reload() error {
	if e.reloads.Add(1) != 1 {
		return nil
	}
	e.startedOnce.Do(func() { close(e.started) })
	select {
	case <-e.release:
		return nil
	case <-e.canceled:
		return context.Canceled
	}
}
func (e *asyncConnectionEngine) CancelActiveApply(context.Context) (bool, error) {
	e.canceledOnce.Do(func() { close(e.canceled) })
	return true, nil
}

func TestGUIConnectionRuleOnlyClosesAfterSuccessfulExplicitRequest(t *testing.T) {
	for _, scenario := range []string{"success-close", "success-keep", "cancel-close", "connection-changed"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			a := newProfileHarness(dir)
			base := []byte("mode: rule\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
			if err := a.importURLData("https://example.invalid/sub", base, nil); err != nil {
				t.Fatal(err)
			}
			var err error
			a.rewrites, err = rewrite.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := a.profiles.Load()
			if err != nil {
				t.Fatal(err)
			}
			item := conn.Item{ID: "connection", Network: "tcp", Host: "example.test", SourceIP: "127.0.0.1", DestinationPort: "443"}
			engine := &asyncConnectionEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir, id: catalog.Current},
				items: []conn.Item{item}, started: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
			defer engine.releaseOnce.Do(func() { close(engine.release) })
			a.core = engine
			change := agent.Change{Scope: "connection", Operation: "set", ConnectionID: item.ID, Policy: "REJECT", TTLSeconds: 60, CloseExisting: scenario != "success-keep"}
			preview, err := a.agentPreview(change)
			if err != nil {
				t.Fatalf("validated connection preview: %v", err)
			}
			if scenario == "connection-changed" {
				engine.items = nil
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			type response struct {
				value agent.ApplyResult
				err   error
			}
			result := make(chan response, 1)
			d.call(func() {
				a.agentApplyAsync(preview.ProposalID, func(value agent.ApplyResult, err error) { result <- response{value, err} })
			})
			if scenario != "connection-changed" {
				select {
				case <-engine.started:
				case <-time.After(5 * time.Second):
					t.Fatal("connection rule reload did not start")
				}
				if engine.closed.Load() != 0 {
					t.Fatal("existing connection was closed before successful apply")
				}
				if scenario == "cancel-close" {
					d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
				} else {
					engine.releaseOnce.Do(func() { close(engine.release) })
				}
			}
			var out response
			select {
			case out = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("connection rule transaction did not finish")
			}
			wantClosed := scenario == "success-close"
			if (out.err == nil) != (scenario == "success-close" || scenario == "success-keep") {
				t.Fatalf("connection apply: %+v %v", out.value, out.err)
			}
			if out.value.ClosedConnection != wantClosed || (engine.closed.Load() != 0) != wantClosed {
				t.Fatalf("unexpected close result: %+v calls=%d", out.value, engine.closed.Load())
			}
			state := a.rewrites.Snapshot()
			if scenario == "cancel-close" || scenario == "connection-changed" {
				if len(state.Connections) != 0 {
					t.Fatal("failed connection rule remained applied")
				}
			} else if len(state.Connections) != 1 || state.Connections[0].ID != item.ID {
				t.Fatal("successful connection rule missing")
			}
		})
	}
}

type delayedGuardedReloadEngine struct {
	coreEngine
	started, release chan struct{}
	calls            atomic.Int32
}

func (e *delayedGuardedReloadEngine) Reload() error {
	if e.calls.Add(1) == 1 {
		close(e.started)
		<-e.release
	}
	return e.coreEngine.Reload()
}

func TestRuleApplyRejectsSourceChangedBeforeKernelComposition(t *testing.T) {
	for _, gui := range []bool{false, true} {
		t.Run(fmt.Sprintf("gui=%t", gui), func(t *testing.T) {
			t.Setenv("CI", "1")
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			preview, err := a.agentPreview(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,preview.test,REJECT"}}})
			if err != nil {
				t.Fatal(err)
			}
			engine := &delayedGuardedReloadEngine{coreEngine: a.core, started: make(chan struct{}), release: make(chan struct{})}
			a.core = engine
			var d *serialDispatcher
			if gui {
				d = newSerialDispatcher()
				a.dispatch = d.call
				defer d.close()
			}
			result := make(chan error, 1)
			if gui {
				d.call(func() { a.agentApplyAsync(preview.ProposalID, func(_ agent.ApplyResult, err error) { result <- err }) })
			} else {
				go func() { _, err := a.agentApply(preview.ProposalID); result <- err }()
			}
			select {
			case <-engine.started:
			case <-time.After(5 * time.Second):
				t.Fatal("reload did not start")
			}
			external := base + "# changed after preview\n"
			if err := os.WriteFile(path, []byte(external), 0600); err != nil {
				t.Fatal(err)
			}
			close(engine.release)
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "source changed") {
					t.Fatalf("source change accepted: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("rule application did not finish")
			}
			if engine.calls.Load() != 1 {
				t.Fatal("unvalidated external configuration was reloaded during rollback")
			}
			if a.agentApplyGuard.Load() != nil {
				t.Fatal("application guard remained installed")
			}
			for _, rule := range a.core.Rules() {
				if rule.Payload == "preview.test" {
					t.Fatal("rule was applied after its source changed")
				}
			}
			current, err := os.ReadFile(path)
			if err != nil || string(current) != external || len(a.rewrites.Snapshot().Global.Prepend) != 0 {
				t.Fatal("source or prior rule state was not preserved")
			}
		})
	}
}
