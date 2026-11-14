package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestHeadlessShutdownInterruptsUncachedProviderReload(t *testing.T) {
	for _, viaAgent := range []bool{true, false} {
		t.Run(fmt.Sprintf("viaAgent=%v", viaAgent), func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enteredOnce, canceledOnce sync.Once
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
					canceledOnce.Do(func() { close(canceled) })
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			engine := core.New()
			a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: engine})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan bool, 1)
			finished := make(chan error, 1)
			go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
			select {
			case <-ready:
			case err := <-finished:
				t.Fatalf("startup: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("startup timed out")
			}
			config := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/uncached.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			client := agent.Client{Dir: dir, Timeout: 5 * time.Second}
			modeDone := make(chan error, 1)
			go func() { modeDone <- client.Call(context.Background(), "mode", agent.ModeArgs{Mode: "direct"}, nil) }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("provider did not begin loading")
			}
			if viaAgent {
				var result agent.ActionResult
				if err := client.Call(context.Background(), "shutdown", nil, &result); err != nil || !result.OK {
					t.Fatalf("shutdown acknowledgement: %+v %v", result, err)
				}
			} else {
				cancel()
			}
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown did not cancel provider initialization")
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatalf("headless shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("headless shutdown waited for provider")
			}
			select {
			case err := <-modeDone:
				if err == nil {
					t.Fatal("interrupted mode change reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("mode request did not finish")
			}
			if engine.Status().Running {
				t.Fatal("kernel still running after shutdown")
			}
			options, err := kernelopts.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if options.Snapshot().Mode != nil {
				t.Fatal("interrupted mode change was not rolled back")
			}
		})
	}
}
