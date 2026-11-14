package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestHeadlessAgentLatencyUsesNodeAndReturnsTimeout(t *testing.T) {
	t.Setenv("CI", "true")
	dir := t.TempDir()
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nproxy-groups: [{name: Test, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	ready, finished := make(chan bool, 1), make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(on bool) { ready <- on }}) }()
	defer func() { cancel(); <-finished }()
	select {
	case on := <-ready:
		if on {
			t.Fatal("TUN unexpectedly enabled")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("headless startup timeout")
	}
	client := agent.Client{Dir: dir}
	for _, tc := range []struct {
		path, state string
		timeout     int
	}{{"/ok", "succeeded", 3000}, {"/slow", "timed_out", 150}} {
		var job agent.DelayJob
		if err := client.Call(context.Background(), "delay-test", agent.DelayArgs{Group: "Test", Node: "DIRECT", URL: srv.URL + tc.path, TimeoutMS: tc.timeout}, &job); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for job.State == "pending" && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			if err := client.Call(context.Background(), "delay-job-status", agent.DelayJobArgs{JobID: job.JobID}, &job); err != nil {
				t.Fatal(err)
			}
		}
		if job.State != tc.state || (tc.state == "succeeded" && job.DelayMS < 1) {
			t.Fatalf("unexpected result for %s: %+v", tc.path, job)
		}
	}
}
