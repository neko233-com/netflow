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

type failRestartStop struct{ coreEngine }

func (*failRestartStop) Stop() error { return errors.New("injected stop error") }

type pauseRestartStop struct {
	coreEngine
	entered, release chan struct{}
	starts           atomic.Int32
}

func (e *pauseRestartStop) Stop() error        { close(e.entered); <-e.release; return nil }
func (e *pauseRestartStop) Start(string) error { e.starts.Add(1); return nil }

func TestRestartRemainsResponsiveAndCanBeCanceled(t *testing.T) {
	t.Setenv("CI", "1")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
		case <-release:
			_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
		}
	}))
	defer provider.Close()
	defer close(release)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatal("kernel did not start")
	}
	next := append(append([]byte(nil), base...), []byte("proxy-providers:\n  slow: {type: http, url: '"+provider.URL+"', path: providers/restart.yaml, interval: 3600, health-check: {enable: false}}\n")...)
	if err := os.WriteFile(path, next, 0600); err != nil {
		t.Fatal(err)
	}
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	if err := a.startAgent(); err != nil {
		t.Fatal(err)
	}
	defer a.stopAgent()
	result := make(chan error, 1)
	client := agent.Client{Dir: dir, Timeout: 30 * time.Second}
	go func() {
		var out agent.ActionResult
		result <- client.Call(context.Background(), "restart-core", nil, &out)
	}()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("restart provider did not begin")
	}
	pulse := make(chan struct{})
	go d.call(func() { close(pulse) })
	select {
	case <-pulse:
	case <-time.After(time.Second):
		t.Fatal("event loop blocked")
	}
	var label string
	d.call(func() { label = a.model.OperationCancelLabel; a.cancelGUIConfigOperation(a.guiOperation) })
	if label != "取消重启" {
		t.Fatal("restart cancellation misrepresented")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled restart succeeded")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("restart cancellation stalled")
	}
	d.call(func() {})
	if a.core.Status().Running || a.model.Home.Running {
		t.Fatal("canceled restart did not report stopped core")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, next) {
		t.Fatal("restart changed the configuration", err)
	}
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	d.call(func() { a.restartCoreAsync(func(err error) { result <- err }) })
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("retry stalled")
	}
	d.call(func() {})
	if !a.core.Status().Running || !a.model.Home.Running {
		t.Fatal("retry did not start core")
	}
}

func TestRestartReportsStopFailureWithoutStarting(t *testing.T) {
	t.Setenv("CI", "1")
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	underlying := a.core
	if !underlying.Status().Running {
		t.Fatal("kernel did not start")
	}
	defer underlying.Stop()
	a.core = &failRestartStop{underlying}
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	result := make(chan error, 1)
	d.call(func() { a.restartCoreAsync(func(err error) { result <- err }) })
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stop failure reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("restart stalled")
	}
	d.call(func() {})
	if !underlying.Status().Running {
		t.Fatal("stop failure disturbed the existing core")
	}
}

func TestCancelRestartDuringStopDoesNotStartAgain(t *testing.T) {
	t.Setenv("CI", "1")
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	underlying := a.core
	defer underlying.Stop()
	engine := &pauseRestartStop{coreEngine: underlying, entered: make(chan struct{}), release: make(chan struct{})}
	a.core = engine
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	result := make(chan error, 1)
	d.call(func() { a.restartCoreAsync(func(err error) { result <- err }) })
	select {
	case <-engine.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not start")
	}
	d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
	close(engine.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled restart succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("restart stalled")
	}
	d.call(func() {})
	if engine.starts.Load() != 0 {
		t.Fatal("canceled restart started the core")
	}
}

func TestHeadlessShutdownDuringRestart(t *testing.T) {
	t.Setenv("CI", "1")
	entered := make(chan struct{})
	var once sync.Once
	provider := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-r.Context().Done()
	}))
	defer provider.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
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
		t.Fatal(err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless not ready")
	}
	next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/restart-headless.yaml, interval: 3600, health-check: {enable: false}}\n"
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		t.Fatal(err)
	}
	client := agent.Client{Dir: dir, Timeout: 30 * time.Second}
	restart := make(chan error, 1)
	go func() {
		var out agent.ActionResult
		restart <- client.Call(context.Background(), "restart-core", nil, &out)
	}()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("provider did not start")
	}
	var out agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &out); err != nil || !out.OK {
		t.Fatalf("shutdown: %+v %v", out, err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("shutdown stalled")
	}
	select {
	case err := <-restart:
		if err == nil {
			t.Fatal("canceled restart reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restart caller did not finish")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != next {
		t.Fatal("shutdown changed config", err)
	}
}
