package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStartContextCancellationDoesNotAffectLaterReload(t *testing.T) {
	t.Setenv("CI", "1")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, canceledOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			canceledOnce.Do(func() { close(canceled) })
		case <-release:
			_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
		}
	}))
	defer server.Close()
	defer unblock()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	engine := New()
	defer engine.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	if err := engine.StartContext(ctx, dir); err != nil {
		t.Fatal(err)
	}
	cancel()
	config := base + "proxy-providers:\n  new: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\n"
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- engine.Reload() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("later reload did not fetch provider")
	}
	select {
	case <-canceled:
		t.Fatal("canceled old context interrupted later reload")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatalf("later reload failed: %v", err)
	}
	if !engine.Status().Running {
		t.Fatal("later reload stopped the core")
	}
}

func TestStartContextRejectsAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New().StartContext(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("start: %v", err)
	}
}

func TestStartContextDeadlineCancelsInitialProvider(t *testing.T) {
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
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nproxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	engine := New()
	defer engine.Stop()
	done := make(chan error, 1)
	go func() { done <- engine.StartContext(ctx, dir) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider did not start before deadline")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup deadline did not complete")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("deadline did not cancel provider request")
	}
	if engine.Status().Running {
		t.Fatal("deadline left core running")
	}
}
