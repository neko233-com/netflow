package app

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestHeadlessDispatcherSerializesAndStops(t *testing.T) {
	d := newSerialDispatcher()
	var value int
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() { defer group.Done(); d.call(func() { value++ }) }()
	}
	group.Wait()
	d.close()
	d.call(func() { value++ })
	if value != 20 {
		t.Fatalf("dispatcher accepted work after shutdown or lost work: %d", value)
	}
	gui := &App{}
	if _, err := gui.agentCommand("shutdown", nil); err == nil {
		t.Fatal("shutdown accepted for GUI instance")
	}
}

func TestHeadlessAgentRewriteAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan bool, 1)
	finished := make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
	select {
	case enabled := <-ready:
		if enabled {
			t.Fatal("TUN started without a request")
		}
	case err := <-finished:
		t.Fatalf("headless exited before ready: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("headless startup timed out")
	}
	client := agent.Client{Dir: dir, Timeout: 20 * time.Second}
	var status agent.Status
	if err := client.Call(context.Background(), "status", nil, &status); err != nil || !status.Running || !status.Headless || status.TUN {
		t.Fatalf("headless status: %+v %v", status, err)
	}
	if err := client.Call(context.Background(), "show", nil, nil); err == nil {
		t.Fatal("headless instance claimed to have a window")
	}
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,headless.example,REJECT"}}}
	var proposal agent.Preview
	if err := client.Call(context.Background(), "preview", change, &proposal); err != nil {
		t.Fatal(err)
	}
	var applied agent.ApplyResult
	if err := client.Call(context.Background(), "apply", agent.ApplyArgs{ProposalID: proposal.ProposalID}, &applied); err != nil {
		t.Fatal(err)
	}
	var result agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &result); err != nil || !result.OK {
		t.Fatalf("shutdown acknowledgement: %+v %v", result, err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("headless shutdown timed out")
	}
	lock, err := appdir.Acquire(dir)
	if err != nil {
		t.Fatalf("configuration lock was not released: %v", err)
	}
	_ = lock.Close()
	if err := client.Call(context.Background(), "status", nil, &status); err == nil {
		t.Fatal("Agent bridge survived shutdown")
	}
}
