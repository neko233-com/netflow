package coreipc

import (
	"errors"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type diagnosticRPC struct{}

func (*diagnosticRPC) Fail(_ Empty, _ *Empty) error { return errors.New("remote rejection") }

type slowCacheRPC struct{ release chan struct{} }

func (s *slowCacheRPC) ProviderCaches(_ ProviderCacheQuery, _ *ProviderCaches) error {
	<-s.release
	return nil
}
func (*slowCacheRPC) Status(_ Empty, out *BoolResult) error { out.Value = true; return nil }

type stopCacheRPC struct{ item ProviderCache }

func (s *stopCacheRPC) Stop(_ ProviderCacheQuery, out *ProviderCaches) error {
	out.Items = []ProviderCache{s.item}
	return nil
}

func TestStopReportsCacheConflictWithoutPretendingKernelIsRunning(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("providers", "cache.yaml")
	if err := os.WriteFile(filepath.Join(dir, path), []byte("user edit"), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	server := rpc.NewServer()
	if err := server.RegisterName("Kernel", &stopCacheRPC{item: ProviderCache{Path: path, Data: []byte("download"), Version: "1"}}); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	c, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.dir = dir
	c.caches = newCacheState([]StageFile{{Path: path, Data: []byte("old")}}, true)
	if err := c.Stop(); err != nil {
		t.Fatalf("stopped core reported as running: %v", err)
	}
	if c.CacheWarning() == "" || c.caches.running {
		t.Fatal("cache conflict warning or stopped state missing")
	}
	data, _ := os.ReadFile(filepath.Join(dir, path))
	if string(data) != "user edit" {
		t.Fatal("user edit was overwritten")
	}
}

func TestSlowCacheReadDoesNotCloseTransport(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	slow := &slowCacheRPC{release: make(chan struct{})}
	if err := server.RegisterName("Kernel", slow); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.readProviderCaches(ProviderCacheQuery{}, 25*time.Millisecond); err == nil {
		t.Fatal("slow read did not time out")
	}
	var status BoolResult
	if err := client.short("Status", Empty{}, &status); err != nil || !status.Value {
		t.Fatalf("cache timeout closed transport: %+v %v", status, err)
	}
	close(slow.release)
}

func TestQueuedProviderUpdateRejectsChangedProfile(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetProfileID("old")
	c.applyMu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); done <- c.UpdateProxyProviderForProfile("nodes", "old") }()
	<-started
	c.SetProfileID("new")
	c.applyMu.Unlock()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "profile changed") {
			t.Fatalf("changed profile accepted: %v", err)
		}
	case <-time.After(time.Second):
		_ = right.Close()
		t.Fatal("update reached the worker after the profile changed")
	}
}

func TestClientAddsWorkerDetailOnlyForTransportErrors(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	if err := server.RegisterName("Kernel", &diagnosticRPC{}); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	want := errors.New("worker exit detail")
	calls := 0
	client.failureDetail = func() error { calls++; return want }
	if err := client.short("Fail", Empty{}, &Empty{}); err == nil || errors.Is(err, want) || calls != 0 {
		t.Fatalf("remote rejection was treated as a transport error: %v", err)
	}
	_ = right.Close()
	err = client.short("Fail", Empty{}, &Empty{})
	if !errors.Is(err, want) || !errors.Is(client.TransportError(), want) || calls != 1 {
		t.Fatalf("transport failure omitted worker detail: %v; calls=%d", err, calls)
	}
}

func TestClientCloseWaitsForWorkerOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("worker did not exit")
	calls := 0
	c.closeHook = func() error { calls++; return want }
	if !errors.Is(c.Close(), want) || !errors.Is(c.Close(), want) || calls != 1 {
		t.Fatalf("close must wait once and preserve the worker error: calls=%d", calls)
	}
}

func TestWorkerOverPrivateConnection(t *testing.T) {
	t.Setenv("CI", "1")
	left, right := net.Pipe()
	worker := NewWorker()
	stopped := make(chan error, 1)
	go func() { stopped <- worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nrules: ['MATCH,DIRECT']\n"
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	client.SetProfileID("profile-1")
	client.SetTransformer(func(data []byte, id string) ([]byte, error) {
		if id != "profile-1" {
			t.Errorf("profile ID = %q", id)
		}
		return append(data, []byte("ipv6: false\n")...), nil
	})
	if err = client.Start(dir); err != nil {
		t.Fatal(err)
	}
	if status := client.Status(); !status.Running || status.TUN {
		t.Fatalf("status %+v", status)
	}
	effective, err := client.EffectiveConfig()
	if err != nil || !strings.Contains(string(effective), "ipv6: false") {
		t.Fatalf("effective %q: %v", effective, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != source {
		t.Fatal("source configuration changed")
	}
	if got := client.Rules(); len(got) != 1 || got[0].Proxy != "DIRECT" {
		t.Fatalf("rules %+v", got)
	}
	if err = client.Reload(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not stop on disconnect")
	}
	if worker.kernel.Status().Running {
		t.Fatal("kernel kept running after disconnect")
	}
}

func TestWorkerRejectsOversizedConfig(t *testing.T) {
	if validConfig(make([]byte, MaxConfigBytes+1)) == nil {
		t.Fatal("oversized config accepted")
	}
	if validConfig(nil) == nil {
		t.Fatal("empty config accepted")
	}
}
