package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestAgentCancelApplyRollsBackProfileSwitch(t *testing.T) {
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
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	next := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\n"
	store := profile.NewStore(dir)
	first, err := store.ImportLocal("first.yaml", []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ImportLocal("second.yaml", []byte(next))
	if err != nil {
		t.Fatal(err)
	}
	engine := core.New()
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: engine})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, finished := make(chan bool, 1), make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("startup: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("startup timeout")
	}
	client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
	var noop agent.CancelApplyResult
	if err := client.Call(context.Background(), "cancel-apply", nil, &noop); err != nil || noop.Accepted {
		t.Fatalf("idle cancel: %+v %v", noop, err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	switched := make(chan error, 1)
	go func() {
		switched <- client.Call(context.Background(), "use-profile", agent.ProfileArgs{ProfileID: second.UID}, nil)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("provider did not start")
	}
	var result agent.CancelApplyResult
	if err := client.Call(context.Background(), "cancel-apply", map[string]any{"unknown": true}, &result); err == nil {
		t.Fatal("invalid cancellation accepted")
	}
	select {
	case <-canceled:
		t.Fatal("invalid request canceled the operation")
	default:
	}
	if err := client.Call(context.Background(), "cancel-apply", nil, &result); err != nil || !result.Accepted {
		t.Fatalf("cancel: %+v %v", result, err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("provider was not canceled")
	}
	select {
	case err := <-switched:
		if err == nil {
			t.Fatal("canceled switch reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("switch did not finish rollback")
	}
	var status agent.Status
	if err := client.Call(context.Background(), "status", nil, &status); err != nil {
		t.Fatalf("status after rollback: %v", err)
	}
	if !status.Running || status.ActiveProfile != first.UID {
		t.Fatalf("wrong kernel after rollback: %+v", status)
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("config was not restored: %v", err)
	}
	catalog, err := store.Load()
	if err != nil || catalog.Current != first.UID {
		t.Fatalf("catalog was not restored: %+v %v", catalog, err)
	}
	result = agent.CancelApplyResult{}
	if err := client.Call(context.Background(), "cancel-apply", nil, &result); err != nil || result.Accepted {
		t.Fatalf("idle cancel after rollback: %+v %v", result, err)
	}
	var shutdown agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
		t.Fatalf("shutdown: %+v %v", shutdown, err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}
}
