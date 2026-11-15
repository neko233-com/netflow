package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestHeadlessAgentTransactionsRestoreStateOnShutdown(t *testing.T) {
	for _, trigger := range []string{"shutdown", "request-cancel", "repeat-cancel"} {
		for _, operation := range []string{"mode", "kernel-option", "use-profile", "apply"} {
			if trigger == "repeat-cancel" && operation != "mode" {
				continue
			}
			t.Run(trigger+"/"+operation, func(t *testing.T) {
				t.Setenv("CI", "1")
				entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				rollbackEntered, rollbackCanceled := make(chan struct{}), make(chan struct{})
				var enteredOnce, canceledOnce, releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				var requests atomic.Int32
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					number := requests.Add(1)
					enteredOnce.Do(func() { close(entered) })
					if number == 2 {
						close(rollbackEntered)
					}
					select {
					case <-r.Context().Done():
						canceledOnce.Do(func() { close(canceled) })
						if number == 2 {
							close(rollbackCanceled)
						}
					case <-release:
						_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
					}
				}))
				defer provider.Close()
				defer unblock()
				dir := t.TempDir()
				base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
				next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/headless-transaction.yaml, interval: 3600, health-check: {enable: false}}\n"
				store := profile.NewStore(dir)
				first, err := store.ImportLocal("first.yaml", []byte(base))
				if err != nil {
					t.Fatal(err)
				}
				second, err := store.ImportLocal("second.yaml", []byte(next))
				if err != nil {
					t.Fatal(err)
				}
				a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ready, finished := make(chan bool, 1), make(chan error, 1)
				go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(v bool) { ready <- v }}) }()
				select {
				case <-ready:
				case err := <-finished:
					t.Fatalf("startup: %v", err)
				case <-time.After(20 * time.Second):
					t.Fatal("headless not ready")
				}
				configPath := filepath.Join(dir, "config.yaml")
				if operation != "use-profile" {
					if err := os.WriteFile(configPath, []byte(next), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				client := agent.Client{Dir: dir, Timeout: 30 * time.Second}
				var args any
				switch operation {
				case "mode":
					args = agent.ModeArgs{Mode: "direct"}
				case "kernel-option":
					enabled := true
					args = agent.KernelOptionArgs{Name: "ipv6", BoolValue: &enabled}
				case "use-profile":
					args = agent.ProfileArgs{ProfileID: second.UID}
				case "apply":
					var preview agent.Preview
					change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,headless-shutdown.test,REJECT"}}}
					if err := client.Call(context.Background(), "preview", change, &preview); err != nil || preview.ProposalID == "" {
						t.Fatalf("preview: %+v %v", preview, err)
					}
					if requests.Load() != 0 {
						t.Fatal("preview unexpectedly downloaded the provider")
					}
					args = agent.ApplyArgs{ProposalID: preview.ProposalID}
				}
				requestCtx, cancelRequest := context.WithCancel(context.Background())
				defer cancelRequest()
				result := make(chan error, 1)
				go func() { result <- client.Call(requestCtx, operation, args, nil) }()
				select {
				case <-entered:
				case err := <-result:
					t.Fatalf("operation returned before provider: %v", err)
				case <-time.After(20 * time.Second):
					t.Fatal("provider did not start")
				}
				pulse := make(chan struct{})
				go a.dispatch(func() { close(pulse) })
				select {
				case <-pulse:
				case <-time.After(time.Second):
					t.Fatal("headless dispatcher blocked during reload")
				}
				var mutated atomic.Bool
				queued := make(chan struct{})
				go func() { a.runOnMain(func() { mutated.Store(true) }); close(queued) }()
				select {
				case <-queued:
					t.Fatal("mutation crossed transaction barrier")
				case <-time.After(100 * time.Millisecond):
				}
				if trigger == "shutdown" {
					var shutdown agent.ActionResult
					if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
						t.Fatalf("shutdown: %+v %v", shutdown, err)
					}
				} else if trigger == "request-cancel" {
					cancelRequest()
				} else {
					var applied agent.CancelApplyResult
					if err := client.Call(context.Background(), "cancel-apply", nil, &applied); err != nil || !applied.Accepted {
						t.Fatalf("initial cancellation: %+v %v", applied, err)
					}
				}
				select {
				case <-canceled:
				case <-time.After(10 * time.Second):
					t.Fatal("provider was not canceled")
				}
				if trigger == "repeat-cancel" {
					select {
					case <-rollbackEntered:
					case <-time.After(10 * time.Second):
						t.Fatal("rollback provider did not start")
					}
					var applied agent.CancelApplyResult
					if err := client.Call(context.Background(), "cancel-apply", nil, &applied); err != nil || applied.Accepted {
						t.Fatalf("rollback cancellation: %+v %v", applied, err)
					}
					select {
					case <-rollbackCanceled:
						t.Fatal("rollback provider was canceled")
					case <-time.After(100 * time.Millisecond):
					}
				}
				if trigger != "shutdown" {
					unblock()
				}
				select {
				case <-queued:
				case <-time.After(5 * time.Second):
					t.Fatal("queued mutation did not return")
				}
				if mutated.Load() != (trigger != "shutdown") {
					t.Fatalf("queued mutation state after %s: %t", trigger, mutated.Load())
				}
				if trigger != "shutdown" {
					var shutdown agent.ActionResult
					if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
						t.Fatalf("shutdown after request cancellation: %+v %v", shutdown, err)
					}
				}
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(20 * time.Second):
					t.Fatal("headless shutdown stalled")
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("interrupted transaction reported success")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("agent request did not finish")
				}
				after, err := os.ReadFile(configPath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("config not restored: %v", err)
				}
				catalog, err := store.Load()
				if err != nil || catalog.Current != first.UID {
					t.Fatalf("profile not restored: %+v %v", catalog, err)
				}
				options, err := kernelopts.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if options.Snapshot().Mode != nil || options.Snapshot().IPv6 != nil {
					t.Fatal("kernel option was not rolled back")
				}
				state, err := rewrite.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Snapshot().Global.Prepend) != 0 || len(state.Snapshot().Global.Append) != 0 || len(state.Snapshot().Global.Remove) != 0 {
					t.Fatal(fmt.Sprintf("rewrite was not rolled back: %+v", state.Snapshot()))
				}
			})
		}
	}
}
