package coreipc

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestStopInterruptsInitialUncachedProvider(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
			_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
		}
	}))
	defer server.Close()
	defer close(release)
	userDir, stageDir := t.TempDir(), t.TempDir()
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	configPath := filepath.Join(userDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	worker.stageFactory = func() (fileStage, error) { return &testStage{dir: stageDir}, nil }
	served := make(chan error, 1)
	go func() { served <- worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(); <-served }()
	client.cacheInterval = time.Hour
	if err := client.Start(userDir); err != nil {
		t.Fatal(err)
	}
	config := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/uncached.yaml, interval: 3600, health-check: {enable: false}}\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan error, 1)
	go func() { reloaded <- client.Reload() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial download did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- client.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for initial download")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("initial download was not canceled")
	}
	select {
	case err := <-reloaded:
		if err == nil {
			t.Fatal("interrupted reload reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted reload did not finish")
	}
	if client.Status().Running {
		t.Fatal("kernel still running")
	}
	if err := os.WriteFile(configPath, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(userDir); err != nil {
		t.Fatalf("restart after interrupted reload: %v", err)
	}
	if err := client.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestDisconnectInterruptsInitialUncachedProvider(t *testing.T) {
	for _, initialStart := range []bool{true, false} {
		t.Run(fmt.Sprintf("initialStart=%v", initialStart), func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			worker := NewWorker()
			served := make(chan error, 1)
			go func() { served <- worker.Serve(right) }()
			client, err := NewClient(left)
			if err != nil {
				t.Fatal(err)
			}
			if !initialStart {
				if err := client.Start(dir); err != nil {
					t.Fatal(err)
				}
			}
			config := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				if initialStart {
					finished <- client.Start(dir)
				} else {
					finished <- client.Reload()
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				_ = client.Close()
				t.Fatal("initial download did not start")
			}
			_ = client.Close()
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("download was not canceled on disconnect")
			}
			select {
			case err := <-served:
				if err != nil {
					t.Fatalf("worker cleanup: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("worker cleanup waited for download")
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("disconnected apply reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("client remained blocked")
			}
		})
	}
}

func TestStopInterruptsInitialUncachedRuleProvider(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	dir := t.TempDir()
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	served := make(chan error, 1)
	go func() { served <- worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(); <-served }()
	if err := client.Start(dir); err != nil {
		t.Fatal(err)
	}
	config := base + "rule-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/rules.yaml, behavior: domain, format: yaml, interval: 3600}\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.Reload() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial rule download did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- client.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for initial rule download")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("initial rule download was not canceled")
	}
	if err := <-done; err == nil {
		t.Fatal("interrupted reload reported success")
	}
}

func TestStopInterruptsSlowProviderAndPreservesCompletedCache(t *testing.T) {
	t.Setenv("CI", "1")
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
	}))
	defer server.Close()
	defer close(release)
	userDir, stageDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"good.yaml", "slow.yaml"} {
		if err := os.WriteFile(filepath.Join(userDir, "providers", name), []byte("proxies: [{name: old, type: direct}]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nproxy-providers:\n" +
		"  good: {type: http, url: '" + server.URL + "/good', path: providers/good.yaml, interval: 3600, health-check: {enable: false}}\n" +
		"  slow: {type: http, url: '" + server.URL + "/slow', path: providers/slow.yaml, interval: 3600, health-check: {enable: false}}\n" +
		"rules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(userDir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	worker.stageFactory = func() (fileStage, error) { return &testStage{dir: stageDir}, nil }
	served := make(chan error, 1)
	go func() { served <- worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(); <-served }()
	client.cacheInterval = time.Hour
	if err := client.Start(userDir); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProxyProvider("good"); err != nil {
		t.Fatal(err)
	}
	update := make(chan error, 1)
	go func() { update <- client.UpdateProxyProvider("slow") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow provider did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- client.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for stalled provider")
	}
	select {
	case err := <-update:
		if err == nil {
			t.Fatal("stalled provider reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("provider update did not cancel")
	}
	for name, expected := range map[string]string{"good.yaml": "fresh", "slow.yaml": "old"} {
		data, err := os.ReadFile(filepath.Join(userDir, "providers", name))
		if err != nil || !strings.Contains(string(data), expected) {
			t.Fatalf("cache %s: %q %v", name, data, err)
		}
	}
	if client.Status().Running {
		t.Fatal("kernel still running")
	}
	if err := client.Start(userDir); err != nil {
		t.Fatalf("restart after stop failed: %v", err)
	}
	if err := client.Stop(); err != nil {
		t.Fatalf("second stop failed: %v", err)
	}
}

type interruptedSnapshotRPC struct{ started, release chan struct{} }

func (s *interruptedSnapshotRPC) ProviderCaches(_ ProviderCacheQuery, _ *ProviderCaches) error {
	close(s.started)
	<-s.release
	return nil
}
func (*interruptedSnapshotRPC) InterruptForStop(_ Empty, _ *Empty) error           { return nil }
func (*interruptedSnapshotRPC) Stop(_ ProviderCacheQuery, _ *ProviderCaches) error { return nil }

func TestStopInterruptsBlockedCacheSnapshot(t *testing.T) {
	left, right := net.Pipe()
	rpcServer := rpc.NewServer()
	fixture := &interruptedSnapshotRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := rpcServer.RegisterName("Kernel", fixture); err != nil {
		t.Fatal(err)
	}
	go rpcServer.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dir = t.TempDir()
	client.caches = newCacheState(nil, true)
	snapshot := make(chan error, 1)
	go func() { client.applyMu.Lock(); defer client.applyMu.Unlock(); snapshot <- client.syncProviderCaches() }()
	<-fixture.started
	stopped := make(chan error, 1)
	go func() { stopped <- client.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(fixture.release)
		t.Fatal("stop waited for cache snapshot")
	}
	if err := <-snapshot; err == nil {
		close(fixture.release)
		t.Fatal("interrupted snapshot succeeded")
	}
	close(fixture.release)
}

type failedFinalStopRPC struct{ started, release chan struct{} }

func (s *failedFinalStopRPC) ProviderCaches(_ ProviderCacheQuery, _ *ProviderCaches) error {
	close(s.started)
	<-s.release
	return nil
}
func (*failedFinalStopRPC) InterruptForStop(_ Empty, _ *Empty) error { return nil }
func (*failedFinalStopRPC) Stop(_ ProviderCacheQuery, _ *ProviderCaches) error {
	return errors.New("synthetic final stop failure")
}

func TestStopReportsKernelAlreadyStoppedWhenFinalExchangeFails(t *testing.T) {
	left, right := net.Pipe()
	rpcServer := rpc.NewServer()
	fixture := &failedFinalStopRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := rpcServer.RegisterName("Kernel", fixture); err != nil {
		t.Fatal(err)
	}
	go rpcServer.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dir = t.TempDir()
	client.caches = newCacheState(nil, true)
	snapshot := make(chan error, 1)
	go func() { client.applyMu.Lock(); defer client.applyMu.Unlock(); snapshot <- client.syncProviderCaches() }()
	<-fixture.started
	err = client.Stop()
	if !errors.Is(err, ErrKernelStoppedBeforeFinalization) {
		close(fixture.release)
		<-snapshot
		t.Fatalf("stopped kernel state not reported: %v", err)
	}
	<-snapshot
	close(fixture.release)
}

type blockingFinalSnapshot struct{ entered, release chan struct{} }

func (*blockingFinalSnapshot) VehicleType() P.VehicleType { return P.HTTP }
func (s *blockingFinalSnapshot) WithSnapshot(func(P.Vehicle, utils.HashType) error) error {
	close(s.entered)
	<-s.release
	return nil
}

func TestFinalCacheSnapshotIsBoundedAndDoesNotWriteLateReply(t *testing.T) {
	fixture := &blockingFinalSnapshot{entered: make(chan struct{}), release: make(chan struct{})}
	var busy atomic.Bool
	out := ProviderCaches{Warning: "untouched"}
	err := collectProviderCachesWithin(t.TempDir(), []providerSnapshot{fixture}, ProviderCacheQuery{}, &out, 30*time.Millisecond, &busy)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		close(fixture.release)
		t.Fatalf("snapshot was not bounded: %v", err)
	}
	<-fixture.entered
	var second ProviderCaches
	if err := collectProviderCachesWithin(t.TempDir(), nil, ProviderCacheQuery{}, &second, time.Second, &busy); err == nil {
		close(fixture.release)
		t.Fatal("second snapshot accepted while first is running")
	}
	close(fixture.release)
	deadline := time.Now().Add(5 * time.Second)
	for busy.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if busy.Load() || out.Warning != "untouched" {
		t.Fatal("late snapshot changed response or did not finish")
	}
}
