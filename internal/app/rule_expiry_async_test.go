package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestRuleExpiryWarningDoesNotExposeKernelSecrets(t *testing.T) {
	a := &App{model: ui.NewModel(ui.HomeState{})}
	a.reportRuleExpiry(errors.New("https://user:synthetic-secret@example.invalid"))
	if strings.Contains(a.model.Notice, "synthetic-secret") || a.rewriteWarning == "" {
		t.Fatal("kernel diagnostic leaked or warning missing")
	}
	a.reportRuleExpiry(context.Canceled)
	if !strings.Contains(a.model.Notice, "已取消") {
		t.Fatal("cancellation was not described")
	}
}

func TestRuleExpiryAsyncKeepsEventLoopResponsive(t *testing.T) {
	for _, scenario := range []string{"success", "cancel", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			dir := t.TempDir()
			base := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t))
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			underlying := a.core
			defer underlying.Stop()
			state := a.rewrites.Snapshot()
			state.Connections = []rewrite.Connection{{ID: "temporary", ProfileID: a.core.ProfileID(), Rule: "DOMAIN,expiry.test,REJECT", ExpiresAt: time.Now().Add(900 * time.Millisecond)}}
			if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
				t.Fatal(err)
			}
			if err := a.core.Reload(); err != nil {
				t.Fatal(err)
			}
			rule := tunnel.Rules()[0]
			meta := &C.Metadata{Host: "expiry.test"}
			if matched, _ := rule.Match(meta, C.RuleMatchHelper{}); !matched {
				t.Fatal("temporary rule not active")
			}
			if wait := time.Until(state.Connections[0].ExpiresAt.Add(30 * time.Millisecond)); wait > 0 {
				time.Sleep(wait)
			}
			if matched, _ := rule.Match(meta, C.RuleMatchHelper{}); matched {
				t.Fatal("expired rule still matched")
			}
			if scenario == "conflict" {
				if err := os.WriteFile(filepath.Join(dir, "agent-rules.json"), []byte("external edit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			engine := &controlledChainReload{coreEngine: underlying, entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
			a.core = engine
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			d.call(func() { a.expireRulesAsync(time.Now(), func(err error) { result <- err }) })
			select {
			case <-engine.entered:
			case err := <-result:
				t.Fatalf("cleanup ended before reload: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("cleanup did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			if scenario == "cancel" {
				d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
			} else {
				close(engine.release)
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(10 * time.Second):
				t.Fatal("cleanup did not finish")
			}
			if scenario == "success" && err != nil {
				t.Fatal(err)
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			if scenario == "conflict" && !errors.Is(err, rewrite.ErrConflict) {
				t.Fatalf("conflict: %v", err)
			}
			if scenario == "conflict" {
				data, _ := os.ReadFile(filepath.Join(dir, "agent-rules.json"))
				if string(data) != "external edit" {
					t.Fatal("external rules overwritten")
				}
			} else {
				current, err := rewrite.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if (len(current.Snapshot().Connections) != 0) != (scenario == "cancel") {
					t.Fatal("cleanup persistence mismatch")
				}
			}
		})
	}
}

func TestHeadlessShutdownDuringRuleExpiryReload(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, canceledOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			canceledOnce.Do(func() { close(canceled) })
			return
		case <-release:
		}
		_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
	}))
	defer provider.Close()
	defer unblock()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan bool, 1)
	finished := make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(v bool) { ready <- v }}) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatal(err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless not ready")
	}
	var setupErr error
	a.runOnMain(func() {
		state := a.rewrites.Snapshot()
		state.Connections = []rewrite.Connection{{ID: "temporary", ProfileID: a.core.ProfileID(), Rule: "DOMAIN,expiry.test,REJECT", ExpiresAt: time.Now().Add(3 * time.Second)}}
		_, setupErr = a.rewrites.Replace(state, state.Revision)
		if setupErr == nil {
			setupErr = a.core.Reload()
		}
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	rule := tunnel.Rules()[0]
	next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/expiry-shutdown.yaml, interval: 3600, health-check: {enable: false}}\n"
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("expiry reload did not block")
	}
	if matched, _ := rule.Match(&C.Metadata{Host: "expiry.test"}, C.RuleMatchHelper{}); matched {
		t.Fatal("expired rule still matched during blocked reload")
	}
	client := agent.Client{Dir: dir, Timeout: 5 * time.Second}
	var shutdown agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
		t.Fatalf("shutdown: %+v %v", shutdown, err)
	}
	select {
	case <-canceled:
	case <-time.After(10 * time.Second):
		t.Fatal("provider was not canceled")
	}
	unblock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("headless shutdown stalled")
	}
	stored, err := rewrite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Snapshot().Connections) != 1 {
		t.Fatal("shutdown did not restore expired state for later cleanup")
	}
}
