package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestGUIKernelOptionsRemainResponsiveAndRollback(t *testing.T) {
	for _, scenario := range []string{"option-cancel", "ports-cancel", "agent-cancel", "option-success"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, released, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once, enteredOnce, canceledOnce sync.Once
			unblock := func() { once.Do(func() { close(released) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
					canceledOnce.Do(func() { close(canceled) })
					return
				case <-released:
				}
				_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
			}))
			defer provider.Close()
			defer unblock()
			dir := t.TempDir()
			config := filepath.Join(dir, "config.yaml")
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			if err := os.WriteFile(config, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/option.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(config, []byte(next), 0600); err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
			if scenario == "agent-cancel" {
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
				enabled := true
				go func() {
					result <- client.Call(context.Background(), "kernel-option", agent.KernelOptionArgs{Name: "ipv6", BoolValue: &enabled}, nil)
				}()
			} else if scenario == "ports-cancel" {
				d.call(func() { a.setKernelPortsAsync(ui.PortSet{Mixed: freePort(t)}, func(err error) { result <- err }) })
			} else {
				d.call(func() { a.setKernelOptionAsync("ipv6", true, func(err error) { result <- err }) })
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("provider did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			if scenario == "option-success" {
				unblock()
			} else if scenario == "agent-cancel" {
				var response agent.CancelApplyResult
				if err := client.Call(context.Background(), "cancel-apply", nil, &response); err != nil || !response.Accepted {
					t.Fatalf("cancel: %+v %v", response, err)
				}
			} else {
				d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
			}
			if scenario != "option-success" {
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("provider was not canceled")
				}
				unblock()
			}
			select {
			case err := <-result:
				if (scenario == "option-success") != (err == nil) {
					t.Fatalf("result: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("transaction did not finish")
			}
			current, err := kernelopts.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "option-success" {
				if current.Snapshot().IPv6 == nil || !*current.Snapshot().IPv6 || !a.core.Status().IPv6 {
					t.Fatal("option not committed")
				}
			} else if current.Snapshot().IPv6 != nil || current.Snapshot().MixedPort != nil {
				t.Fatal("options not rolled back")
			}
		})
	}
}
