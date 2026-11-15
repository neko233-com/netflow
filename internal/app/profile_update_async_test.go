package app

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type pendingCancelEngine struct {
	coreEngine
	calls atomic.Int32
}

func (e *pendingCancelEngine) CancelActiveApply(context.Context) (bool, error) {
	e.calls.Add(1)
	return true, nil
}

func TestProfileUpdateReloadIsCancelableAndResponsive(t *testing.T) {
	for _, scenario := range []string{"gui-cancel", "headless-agent-cancel", "url-cancel", "success", "external-profile", "external-config", "external-catalog", "shared-cancel"} {
		t.Run(scenario, func(t *testing.T) {
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
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/update.yaml, interval: 3600, health-check: {enable: false}}\n"
			subscription := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, next) }))
			defer subscription.Close()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			if err := a.importURLData(subscription.URL, []byte(base), nil); err != nil {
				t.Fatal(err)
			}
			catalog, err := a.profiles.Load()
			if err != nil || len(catalog.Items) != 1 {
				t.Fatal(err)
			}
			uid, profileFile := catalog.Current, catalog.Items[0].File
			if scenario == "shared-cancel" {
				if err := a.importURLData(subscription.URL+"/second", []byte(base), nil); err != nil {
					t.Fatal(err)
				}
				f, snapshot, err := a.profiles.LoadForUpdate()
				if err != nil {
					t.Fatal(err)
				}
				f.Items[1].File = profileFile
				if err := a.profiles.SaveIfUnchanged(f, snapshot); err != nil {
					t.Fatal(err)
				}
			}
			oldProfile, err := os.ReadFile(filepath.Join(dir, profileFile))
			if err != nil {
				t.Fatal(err)
			}
			oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			oldCatalog, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			if scenario == "headless-agent-cancel" {
				a.headless = true
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
			}
			d.call(func() {
				if scenario == "url-cancel" {
					a.changeProfileURLAsync(uid, subscription.URL+"/replacement", func(err error) { result <- err })
				} else {
					a.updateProfileAsync(uid, func(err error) { result <- err })
				}
			})
			select {
			case <-entered:
			case err := <-result:
				t.Fatalf("update ended before reload: %v", err)
			case <-time.After(15 * time.Second):
				t.Fatal("provider did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			var op *guiConfigOperation
			d.call(func() { op = a.guiOperation })
			if op == nil {
				t.Fatal("missing transaction")
			}
			switch scenario {
			case "external-profile":
				if err := os.WriteFile(filepath.Join(dir, profileFile), []byte("external profile"), 0600); err != nil {
					t.Fatal(err)
				}
			case "external-config":
				if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("external config"), 0600); err != nil {
					t.Fatal(err)
				}
			case "external-catalog":
				if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte("external catalog"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "success" || scenario == "external-catalog" {
				unblock()
			} else if scenario == "headless-agent-cancel" {
				client := agent.Client{Dir: dir, Timeout: 5 * time.Second}
				var response agent.CancelApplyResult
				if err := client.Call(context.Background(), "cancel-apply", nil, &response); err != nil || !response.Accepted {
					t.Fatalf("cancel: %+v %v", response, err)
				}
			} else {
				d.call(func() { a.cancelGUIConfigOperation(op) })
			}
			if scenario != "success" && scenario != "external-catalog" {
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("provider did not cancel")
				}
				unblock()
			}
			var updateErr error
			select {
			case updateErr = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("update did not finish")
			}
			select {
			case <-op.done:
			case <-time.After(time.Second):
				t.Fatal("barrier not released")
			}
			if (scenario == "success") != (updateErr == nil) {
				t.Fatalf("unexpected result: %v", updateErr)
			}
			profileAfter, _ := os.ReadFile(filepath.Join(dir, profileFile))
			configAfter, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
			catalogAfter, _ := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if scenario == "external-profile" {
				if string(profileAfter) != "external profile" || !strings.Contains(updateErr.Error(), "检查运行中的内核") {
					t.Fatal("profile conflict lost", updateErr)
				}
			} else if scenario != "success" && !bytes.Equal(profileAfter, oldProfile) {
				t.Fatal("profile not restored")
			}
			if scenario == "external-config" {
				if string(configAfter) != "external config" || !strings.Contains(updateErr.Error(), "检查运行中的内核") {
					t.Fatal("config conflict lost", updateErr)
				}
			} else if scenario != "success" && !bytes.Equal(configAfter, oldConfig) {
				t.Fatal("config not restored")
			}
			if scenario == "external-catalog" {
				if string(catalogAfter) != "external catalog" {
					t.Fatal("catalog edit lost")
				}
			} else if scenario != "success" && !bytes.Equal(catalogAfter, oldCatalog) {
				t.Fatal("catalog not restored")
			}
			if scenario == "success" && (!bytes.Equal(profileAfter, []byte(next)) || !bytes.Contains(configAfter, []byte("providers/update.yaml"))) {
				t.Fatal("successful update not committed")
			}
			if scenario == "shared-cancel" {
				matches, err := filepath.Glob(filepath.Join(dir, "profiles", "netflow-*.yaml"))
				if err != nil || len(matches) != 0 {
					t.Fatalf("shared staged file was not removed: %v %v", matches, err)
				}
			}
		})
	}
}

func TestHeadlessShutdownRestoresPendingProfileUpdate(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, canceledOnce sync.Once
	provider := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			canceledOnce.Do(func() { close(canceled) })
		case <-release:
		}
	}))
	defer provider.Close()
	defer close(release)
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/shutdown.yaml, interval: 3600, health-check: {enable: false}}\n"
	subscription := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, next) }))
	defer subscription.Close()
	dir := t.TempDir()
	harness := newProfileHarness(dir)
	if err := harness.importURLData(subscription.URL, []byte(base), nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := harness.profiles.Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal(err)
	}
	uid, path := catalog.Current, filepath.Join(dir, catalog.Items[0].File)
	oldProfile, err := os.ReadFile(path)
	if err != nil {
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
		t.Fatalf("headless exited: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless not ready")
	}
	oldConfig, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
	var job agent.ProfileJob
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: uid}, &job); err != nil || job.JobID == "" {
		t.Fatalf("update job: %+v %v", job, err)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("provider did not block")
	}
	var shutdown agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
		t.Fatalf("shutdown: %+v %v", shutdown, err)
	}
	select {
	case <-canceled:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not cancel provider")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("headless shutdown stalled")
	}
	profileAfter, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(profileAfter, oldProfile) {
		t.Fatalf("profile not restored: %v", err)
	}
	configAfter, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || !bytes.Equal(configAfter, oldConfig) {
		t.Fatalf("config not restored: %v", err)
	}
	lock, err := appdir.Acquire(dir)
	if err != nil {
		t.Fatalf("config lock not released: %v", err)
	}
	_ = lock.Close()
}

func TestHeadlessShutdownCancelsSubscriptionDownload(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, canceledOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			canceledOnce.Do(func() { close(canceled) })
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	dir := t.TempDir()
	harness := newProfileHarness(dir)
	if err := harness.importURLData(server.URL, base, nil); err != nil {
		t.Fatal(err)
	}
	catalog, err := harness.profiles.Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal(err)
	}
	uid, path := catalog.Current, filepath.Join(dir, catalog.Items[0].File)
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan bool, 1)
	finished := make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(v bool) { ready <- v }}) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("headless exited: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless not ready")
	}
	client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
	var job agent.ProfileJob
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: uid}, &job); err != nil || job.JobID == "" {
		t.Fatalf("update job: %+v %v", job, err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("download did not start")
	}
	var shutdown agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
		t.Fatalf("shutdown: %+v %v", shutdown, err)
	}
	select {
	case <-canceled:
	case <-time.After(10 * time.Second):
		t.Fatal("download not canceled")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown stalled")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, base) {
		t.Fatal("download changed subscription", err)
	}
}

func TestHeadlessShutdownBeforeTransactionBegins(t *testing.T) {
	engine := &pendingCancelEngine{}
	a := &App{headless: true, core: engine}
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	var op *guiConfigOperation
	finished := make(chan error, 1)
	d.call(func() {
		a.startGUIConfigOperation("test", func() (*guiConfigTransaction, error) {
			t.Error("canceled transaction began")
			return nil, errors.New("unexpected")
		}, func(err error) { finished <- err })
		op = a.guiOperation
		if op == nil || a.guiBarrier.Load() != op {
			t.Fatal("pending transaction did not establish barrier")
		}
		a.headlessStopping.Store(true)
		op.quit = true
		a.cancelGUIConfigOperation(op)
	})
	select {
	case <-op.done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish queued transaction")
	}
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("result: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if engine.calls.Load() != 0 {
		t.Fatal("cancel before reload could affect a later operation")
	}
	called := false
	a.runOnMain(func() { called = true })
	if called {
		t.Fatal("shutdown accepted new mutation")
	}
}
