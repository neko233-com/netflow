package coreipc

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type blockedCancelRPC struct{ entered, release chan struct{} }

func (s *blockedCancelRPC) CancelApply(_ ApplyCancellation, _ *BoolResult) error {
	close(s.entered)
	<-s.release
	return nil
}
func (*blockedCancelRPC) Capabilities(_ Empty, _ *Capabilities) error { return nil }

func TestCancelApplyTimeoutKeepsTransportOpen(t *testing.T) {
	left, right := net.Pipe()
	server := rpc.NewServer()
	blocked := &blockedCancelRPC{entered: make(chan struct{}), release: make(chan struct{})}
	if err := server.RegisterName("Kernel", blocked); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(right)
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer close(blocked.release)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.CancelActiveApply(ctx); done <- err }()
	<-blocked.entered
	if err := <-done; err == nil {
		t.Fatal("cancel did not time out")
	}
	var capabilities Capabilities
	if err := client.short("Capabilities", Empty{}, &capabilities); err != nil || client.TransportError() != nil {
		t.Fatalf("transport closed after timeout: %v", err)
	}
}

func TestCancelApplyInterruptsUncachedProviderAndAllowsRollback(t *testing.T) {
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
	userDir, stageDir := t.TempDir(), t.TempDir()
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	path := filepath.Join(userDir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
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
	if accepted, err := client.CancelActiveApply(context.Background()); err != nil || accepted {
		t.Fatalf("idle cancel: %v %v", accepted, err)
	}
	config := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan error, 1)
	go func() { reloaded <- client.Reload() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not start")
	}
	var expired BoolResult
	if err := worker.CancelApply(ApplyCancellation{Deadline: time.Now().Add(-time.Second).UnixNano()}, &expired); err == nil || expired.Value {
		t.Fatalf("expired cancellation accepted: %+v %v", expired, err)
	}
	select {
	case <-canceled:
		t.Fatal("expired request canceled the provider")
	default:
	}
	if accepted, err := client.CancelActiveApply(context.Background()); err != nil || !accepted {
		t.Fatalf("cancel: %v %v", accepted, err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not cancel")
	}
	select {
	case err := <-reloaded:
		if err == nil {
			t.Fatal("canceled reload reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not finish")
	}
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.Reload(); err != nil {
		t.Fatalf("rollback reload: %v", err)
	}
	if !client.Status().Running {
		t.Fatal("rollback stopped the core")
	}
	if accepted, err := client.CancelActiveApply(context.Background()); err != nil || accepted {
		t.Fatalf("idle cancel after rollback: %v %v", accepted, err)
	}
	if err := client.Stop(); err != nil {
		t.Fatal(err)
	}
}
