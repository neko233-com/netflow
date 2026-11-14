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
)

type blockedUpdateRPC struct{ started, release chan struct{} }

type blockedSnapshotRPC struct{ started, release chan struct{} }

func (*blockedSnapshotRPC) PauseProviderUpdates(_ ProviderPause, _ *Empty) error { return nil }
func (*blockedSnapshotRPC) ResumeProviderUpdates(_ Name, _ *Empty) error         { return nil }

func TestReloadDoesNotOverwritePendingProviderSnapshot(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	blocked := &blockedSnapshotRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := server.RegisterName("Kernel", blocked); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dir = t.TempDir()
	client.caches = newCacheState(nil, true)
	finished := make(chan error, 1)
	go func() { client.applyMu.Lock(); defer client.applyMu.Unlock(); finished <- client.syncProviderCaches() }()
	<-blocked.started
	started := time.Now()
	err = client.Reload()
	if err == nil || !strings.Contains(err.Error(), "previous provider cache snapshot") {
		close(blocked.release)
		t.Fatalf("expected safe snapshot failure: %v", err)
	}
	if time.Since(started) > time.Second {
		close(blocked.release)
		t.Fatal("reload waited for blocked snapshot")
	}
	if err := <-finished; err == nil || !strings.Contains(err.Error(), "interrupted by reload") {
		close(blocked.release)
		t.Fatalf("snapshot was not interrupted: %v", err)
	}
	if err := client.Reload(); err == nil || !strings.Contains(err.Error(), "previous provider cache snapshot") {
		close(blocked.release)
		t.Fatalf("rollback reload must not overwrite pending cache: %v", err)
	}
	if err := client.TryReload(); !errors.Is(err, ErrKernelBusy) {
		close(blocked.release)
		t.Fatalf("TUN reload must not overwrite pending cache: %v", err)
	}
	close(blocked.release)
}

type blockedPauseRPC struct{ started, release chan struct{} }

func (s *blockedPauseRPC) PauseProviderUpdates(_ ProviderPause, _ *Empty) error {
	close(s.started)
	<-s.release
	return nil
}
func (*blockedPauseRPC) Capabilities(_ Empty, _ *Capabilities) error { return nil }

func TestPauseTimeoutDoesNotCloseHealthyTransport(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	blocked := &blockedPauseRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := server.RegisterName("Kernel", blocked); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		result <- client.providerPauseCall("PauseProviderUpdates", ProviderPause{}, 20*time.Millisecond)
	}()
	<-blocked.started
	if err := <-result; err == nil {
		t.Fatal("expected pause timeout")
	}
	var cap Capabilities
	if err := client.short("Capabilities", Empty{}, &cap); err != nil {
		t.Fatalf("transport was closed: %v", err)
	}
	close(blocked.release)
}

func (s *blockedSnapshotRPC) ProviderCaches(_ ProviderCacheQuery, _ *ProviderCaches) error {
	close(s.started)
	<-s.release
	return nil
}

func TestReloadCancelsBlockedUpdateAndProviderRemainsUsable(t *testing.T) {
	for _, failReload := range []bool{false, true} {
		t.Run(fmt.Sprintf("failReload=%v", failReload), func(t *testing.T) {
			t.Setenv("CI", "1")
			started := make(chan struct{})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					close(started)
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
			}))
			defer server.Close()
			userDir, stageDir := t.TempDir(), t.TempDir()
			if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
				t.Fatal(err)
			}
			cache := filepath.Join(userDir, "providers", "proxy.yaml")
			old := "proxies: [{name: old, type: direct}]\n"
			if err := os.WriteFile(cache, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nproxy-providers:\n  test: {type: http, url: '" + server.URL + "', path: providers/proxy.yaml, interval: 3600, health-check: {enable: false}}\nrules: ['MATCH,DIRECT']\n"
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
			update := make(chan error, 1)
			go func() { update <- client.UpdateProxyProvider("test") }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not start")
			}
			if failReload {
				client.SetTransformer(func([]byte, string) ([]byte, error) { return nil, errors.New("invalid edit") })
			}
			begin := time.Now()
			err = client.Reload()
			if (err != nil) != failReload {
				t.Fatalf("reload: %v", err)
			}
			if time.Since(begin) > 5*time.Second {
				t.Fatal("reload waited for blocked network request")
			}
			if err := <-update; err == nil {
				t.Fatal("blocked update was not canceled")
			}
			if got, err := os.ReadFile(cache); err != nil || string(got) != old {
				t.Fatalf("old cache lost: %q %v", got, err)
			}
			if err := client.UpdateProxyProvider("test"); err != nil {
				t.Fatalf("update after reload: %v", err)
			}
			if got, err := os.ReadFile(cache); err != nil || !strings.Contains(string(got), "fresh") {
				t.Fatalf("fresh cache missing: %q %v", got, err)
			}
			if err := client.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTryReloadDoesNotWaitForProviderCacheSnapshot(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	blocked := &blockedSnapshotRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := server.RegisterName("Kernel", blocked); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dir = t.TempDir()
	client.caches = newCacheState(nil, true)
	finished := make(chan error, 1)
	go func() { client.applyMu.Lock(); defer client.applyMu.Unlock(); finished <- client.syncProviderCaches() }()
	<-blocked.started
	if err := client.TryReload(); !errors.Is(err, ErrKernelBusy) {
		close(blocked.release)
		<-finished
		t.Fatalf("expected busy while cache snapshot is in progress: %v", err)
	}
	close(blocked.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func (s *blockedUpdateRPC) UpdateProxyProvider(_ Name, _ *Empty) error {
	close(s.started)
	<-s.release
	return nil
}

func TestRealProviderUpdateMakesTryReloadRetryableWithoutDataLoss(t *testing.T) {
	t.Setenv("CI", "1")
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
			_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	userDir, stageDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(userDir, "providers", "proxy.yaml")
	old := "proxies: [{name: old, type: direct}]\n"
	if err := os.WriteFile(cache, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nproxy-providers:\n  test: {type: http, url: '" + server.URL + "', path: providers/proxy.yaml, interval: 3600, health-check: {enable: false}}\nrules: ['MATCH,DIRECT']\n"
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
	updated := make(chan error, 1)
	go func() { updated <- client.UpdateProxyProvider("test") }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("provider request did not start")
	}
	if err := client.TryReload(); !errors.Is(err, ErrKernelBusy) {
		close(release)
		<-updated
		t.Fatalf("expected busy: %v", err)
	}
	if status := client.Status(); !status.Running {
		close(release)
		<-updated
		t.Fatal("kernel stopped on rejected reload")
	}
	if data, err := os.ReadFile(cache); err != nil || string(data) != old {
		close(release)
		<-updated
		t.Fatal("cache changed while update was pending")
	}
	close(release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(cache); err != nil || !strings.Contains(string(data), "fresh") {
		t.Fatal("completed provider update was not saved")
	}
	if err := client.TryReload(); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if err := client.Stop(); err != nil {
		t.Fatal(err)
	}
}
func (*blockedUpdateRPC) Capabilities(_ Empty, _ *Capabilities) error { return nil }
func (*blockedUpdateRPC) Reload(_ Apply, _ *Empty) error              { return nil }

func TestReloadDoesNotWaitForProviderNetworkOperation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("rules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	server := rpc.NewServer()
	blocked := &blockedUpdateRPC{started: make(chan struct{}), release: make(chan struct{})}
	if err := server.RegisterName("Kernel", blocked); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.dir = dir
	updated := make(chan error, 1)
	go func() { updated <- client.UpdateProxyProvider("remote") }()
	<-blocked.started
	reloaded := make(chan error, 1)
	go func() { reloaded <- client.TryReload() }()
	select {
	case err := <-reloaded:
		if !errors.Is(err, ErrKernelBusy) {
			close(blocked.release)
			<-updated
			t.Fatalf("expected a retryable busy error, got %v", err)
		}
	case <-time.After(time.Second):
		close(blocked.release)
		<-updated
		<-reloaded
		t.Fatal("reload waited for provider network operation")
	}
	close(blocked.release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if err := client.TryReload(); err != nil {
		t.Fatalf("reload after provider update: %v", err)
	}
}
