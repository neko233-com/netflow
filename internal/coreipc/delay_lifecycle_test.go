package coreipc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkerStopCancelsInFlightDelay(t *testing.T) {
	dir := t.TempDir()
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
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
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	probe := make(chan error, 1)
	go func() { _, err := client.TestDelay("", "DIRECT", srv.URL, 30*time.Second); probe <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker probe did not reach server")
	}
	if err := client.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-probe:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("worker probe was not canceled: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker probe did not stop")
	}
}
