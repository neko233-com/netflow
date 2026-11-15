package coreipc

import (
	"context"
	"errors"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type previewCacheRPC struct {
	started, release chan struct{}
	item             ProviderCache
}

func (s *previewCacheRPC) ProviderCaches(_ ProviderCacheQuery, out *ProviderCaches) error {
	close(s.started)
	<-s.release
	out.Items = []ProviderCache{s.item}
	return nil
}
func (*previewCacheRPC) Status(_ Empty, out *BoolResult) error { out.Value = true; return nil }

func TestPreviewCacheSnapshot(t *testing.T) {
	for _, scenario := range []string{"success", "cancel", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join("providers", "cache.yaml")
			if err := os.Mkdir(filepath.Join(dir, "providers"), 0700); err != nil {
				t.Fatal(err)
			}
			if scenario == "conflict" {
				if err := os.WriteFile(filepath.Join(dir, path), []byte("user"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			left, right := net.Pipe()
			server := rpc.NewServer()
			service := &previewCacheRPC{started: make(chan struct{}), release: make(chan struct{}), item: ProviderCache{Path: path, Version: "1", Data: []byte("fresh")}}
			if err := server.RegisterName("Kernel", service); err != nil {
				t.Fatal(err)
			}
			go server.ServeConn(right)
			client, err := NewClient(left)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.dir = dir
			client.caches = newCacheState(nil, true)
			client.applyMu.Lock()
			if err := client.SyncProviderCachesForPreview(context.Background()); !errors.Is(err, ErrKernelBusy) {
				t.Fatalf("busy: %v", err)
			}
			client.applyMu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- client.SyncProviderCachesForPreview(ctx) }()
			select {
			case <-service.started:
			case <-time.After(time.Second):
				t.Fatal("snapshot did not start")
			}
			if scenario == "cancel" {
				cancel()
			} else {
				close(service.release)
			}
			select {
			case err = <-done:
			case <-time.After(time.Second):
				t.Fatal("snapshot did not finish")
			}
			switch scenario {
			case "success":
				if err != nil {
					t.Fatal(err)
				}
				data, e := os.ReadFile(filepath.Join(dir, path))
				if e != nil || string(data) != "fresh" {
					t.Fatalf("snapshot: %q %v", data, e)
				}
			case "conflict":
				if err == nil {
					t.Fatal("external edit accepted")
				}
				data, e := os.ReadFile(filepath.Join(dir, path))
				if e != nil || string(data) != "user" {
					t.Fatalf("external edit lost: %q %v", data, e)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				close(service.release)
				var status BoolResult
				if err := client.short("Status", Empty{}, &status); err != nil || !status.Value {
					t.Fatalf("transport: %v", err)
				}
				if _, e := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(e) {
					t.Fatal("canceled snapshot persisted")
				}
			}
		})
	}
}
