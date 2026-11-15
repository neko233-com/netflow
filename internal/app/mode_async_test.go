package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIModeSwitchRemainsResponsiveAndRollsBack(t *testing.T) {
	for _, scenario := range []string{"cancel", "agent-cancel", "headless-agent-cancel", "success", "external-options"} {
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
			config := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(config, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/mode.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(config, []byte(next), 0600); err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			a.headless = scenario == "headless-agent-cancel"
			defer d.close()
			result := make(chan error, 1)
			client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
			if scenario == "agent-cancel" || scenario == "headless-agent-cancel" {
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
				go func() { result <- client.Call(context.Background(), "mode", agent.ModeArgs{Mode: "direct"}, nil) }()
			} else {
				d.call(func() { a.setModeAsync("direct", func(err error) { result <- err }) })
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("mode provider did not begin")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked during mode change")
			}
			gated := make(chan struct{})
			go a.runOnMain(func() { close(gated) })
			select {
			case <-gated:
				t.Fatal("mutation callback ran during mode change")
			case <-time.After(100 * time.Millisecond):
			}
			if scenario == "success" {
				unblock()
			} else {
				if scenario == "external-options" {
					if err := os.WriteFile(filepath.Join(dir, "kernel-options.json"), []byte("{\"log_level\":\"debug\",\"external\":true}\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "agent-cancel" || scenario == "headless-agent-cancel" {
					var response agent.CancelApplyResult
					if err := client.Call(context.Background(), "cancel-apply", nil, &response); err != nil || !response.Accepted {
						t.Fatalf("Agent cancel: %+v %v", response, err)
					}
				} else {
					d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
				}
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("mode provider was not canceled")
				}
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(15 * time.Second):
				t.Fatal("mode transaction did not finish")
			}
			if scenario == "success" && err != nil {
				t.Fatalf("mode switch: %v", err)
			}
			if scenario != "success" && err == nil {
				t.Fatal("canceled mode switch reported success")
			}
			select {
			case <-gated:
			case <-time.After(5 * time.Second):
				t.Fatal("queued callback did not resume")
			}
			if scenario == "external-options" {
				data, readErr := os.ReadFile(filepath.Join(dir, "kernel-options.json"))
				if readErr != nil || !strings.Contains(string(data), "external") || !strings.Contains(err.Error(), "恢复原设置失败") {
					t.Fatalf("external options conflict was not preserved: %s %v", data, err)
				}
				return
			}
			current, err := kernelopts.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "success" {
				if current.Snapshot().Mode == nil || *current.Snapshot().Mode != "direct" || a.core.Status().Mode != "direct" {
					t.Fatal("mode was not committed")
				}
			} else if current.Snapshot().Mode != nil || a.core.Status().Mode != "rule" {
				t.Fatal("mode was not restored")
			}
			data, err := os.ReadFile(config)
			if err != nil || string(data) != next {
				t.Fatal("mode change overwrote the externally updated subscription")
			}
		})
	}
}
