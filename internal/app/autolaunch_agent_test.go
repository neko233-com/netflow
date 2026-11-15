package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type fakeLoginStartup struct {
	mu      sync.Mutex
	enabled bool
	setErr  error
}

func (s *fakeLoginStartup) Current() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled, nil
}

func (s *fakeLoginStartup) Set(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.enabled = enabled
	return nil
}

func TestHeadlessAgentControlsActualLoginStartup(t *testing.T) {
	dir := t.TempDir()
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	startup := &fakeLoginStartup{}
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New(), AutoStart: startup})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan bool, 1), make(chan error, 1)
	go func() { done <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(on bool) { ready <- on }}) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("headless startup: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless startup timed out")
	}
	defer func() { cancel(); <-done }()
	client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
	var result agent.AutoLaunchResult
	if err := client.Call(context.Background(), "auto-launch", nil, &result); err != nil || result.Enabled || result.AppliesTo != "gui" {
		t.Fatalf("initial login startup: %+v %v", result, err)
	}
	enabled := true
	if err := client.Call(context.Background(), "auto-launch-set", agent.AutoLaunchArgs{Enabled: &enabled}, &result); err != nil || !result.Enabled {
		t.Fatalf("enable login startup: %+v %v", result, err)
	}
	if err := client.Call(context.Background(), "auto-launch-set", agent.AutoLaunchArgs{}, &result); err == nil {
		t.Fatal("missing enabled value was accepted")
	}
	startup.mu.Lock()
	startup.setErr = errors.New("foreign startup entry")
	startup.mu.Unlock()
	enabled = false
	if err := client.Call(context.Background(), "auto-launch-set", agent.AutoLaunchArgs{Enabled: &enabled}, &result); err == nil {
		t.Fatal("conflicting startup entry was changed")
	}
	if err := client.Call(context.Background(), "auto-launch", nil, &result); err != nil || !result.Enabled {
		t.Fatalf("startup state changed after failure: %+v %v", result, err)
	}
	startup.mu.Lock()
	startup.setErr = nil
	startup.enabled = false // external change, read back from the controller
	startup.mu.Unlock()
	if err := client.Call(context.Background(), "auto-launch", nil, &result); err != nil || result.Enabled {
		t.Fatalf("external change was not observed: %+v %v", result, err)
	}
	var status agent.Status
	if err := client.Call(context.Background(), "status", nil, &status); err != nil || status.TUN {
		t.Fatalf("login startup changed current TUN: %+v %v", status, err)
	}
}
