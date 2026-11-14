package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestHeadlessAgentManagesSubscriptions(t *testing.T) {
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\nipv6: false\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	var hold atomic.Bool
	started, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscription" {
			http.NotFound(w, r)
			return
		}
		if hold.Load() {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte(config))
	}))
	defer server.Close()
	defer releaseOnce.Do(func() { close(release) })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan bool, 1)
	finished := make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
	defer func() { cancel(); <-finished }()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("headless startup timed out")
	}
	client := agent.Client{Dir: dir, Timeout: 20 * time.Second}
	wait := func(job agent.ProfileJob) agent.ProfileJob {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for job.State == "pending" && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
			if err := client.Call(context.Background(), "profile-job-status", agent.ProfileJobArgs{JobID: job.JobID}, &job); err != nil {
				t.Fatal(err)
			}
		}
		return job
	}
	importOne := func(name, address string) agent.ProfileJob {
		t.Helper()
		var job agent.ProfileJob
		err := client.Call(context.Background(), "import-profile", agent.ProfileImportArgs{URL: address, Name: name}, &job)
		if err != nil {
			t.Fatal(err)
		}
		return wait(job)
	}
	url := server.URL + "/subscription?token=synthetic-secret"
	first := importOne("first", url)
	if first.State != "succeeded" || first.ProfileID == "" {
		t.Fatalf("first import: %+v", first)
	}
	var list agent.ProfileList
	if err := client.Call(context.Background(), "profiles", nil, &list); err != nil || len(list.Profiles) != 1 || !list.Profiles[0].Active {
		t.Fatalf("profiles: %+v %v", list, err)
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), server.URL) {
		t.Fatal("profile list leaked URL")
	}
	var job agent.ProfileJob
	hold.Store(true)
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: first.ProfileID}, &job); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("profile update did not start")
	}
	var duplicate agent.ProfileJob
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: first.ProfileID}, &duplicate); err != nil || duplicate.JobID != job.JobID {
		t.Fatal("concurrent Agent update was not deduplicated")
	}
	var overlapping error
	a.runOnMain(func() { a.updateProfileAsync(first.ProfileID, func(err error) { overlapping = err }) })
	if overlapping == nil {
		t.Fatal("GUI update was allowed to overlap the Agent update")
	}
	hold.Store(false)
	releaseOnce.Do(func() { close(release) })
	if job = wait(job); job.State != "succeeded" {
		t.Fatalf("update: %+v", job)
	}
	if err := client.Call(context.Background(), "delete-profile", agent.ProfileArgs{ProfileID: first.ProfileID}, nil); err == nil {
		t.Fatal("active profile was deleted")
	}
	second := importOne("second", url)
	if second.State != "succeeded" || second.ProfileID == "" || second.ProfileID == first.ProfileID {
		t.Fatalf("second import: %+v", second)
	}
	var deleted agent.ActionResult
	if err := client.Call(context.Background(), "delete-profile", agent.ProfileArgs{ProfileID: second.ProfileID}, &deleted); err != nil || !deleted.OK {
		t.Fatalf("delete inactive profile: %+v %v", deleted, err)
	}
	failed := importOne("failure", server.URL+"/missing?token=synthetic-secret")
	encoded, _ = json.Marshal(failed)
	if failed.State != "failed" || strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), server.URL) {
		t.Fatalf("failed import was not redacted: %s", encoded)
	}
}
