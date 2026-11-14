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
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
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

func TestHeadlessAgentCreatesRunningBackup(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "config")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	ready, finished := make(chan bool, 1), make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
	defer func() { cancel(); <-finished }()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("headless startup timed out")
	}
	client := agent.Client{Dir: dir, Timeout: 20 * time.Second}
	archive := filepath.Join(base, "backup.zip")
	var job agent.BackupJob
	if err := client.Call(context.Background(), "backup-create", agent.BackupArgs{Path: archive}, &job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for job.State == "pending" && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		if err := client.Call(context.Background(), "backup-job-status", agent.BackupJobArgs{JobID: job.JobID}, &job); err != nil {
			t.Fatal(err)
		}
	}
	if job.State != "succeeded" {
		t.Fatalf("live backup failed: %+v", job)
	}
	target := filepath.Join(base, "restored")
	var restore agent.BackupJob
	if err := client.Call(context.Background(), "restore-create", agent.RestoreArgs{Archive: archive, Destination: filepath.Join(dir, "inside")}, &restore); err == nil {
		t.Fatal("restore was allowed inside the active configuration")
	}
	if err := client.Call(context.Background(), "restore-create", agent.RestoreArgs{Archive: archive, Destination: target}, &restore); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for restore.State == "pending" && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		if err := client.Call(context.Background(), "backup-job-status", agent.BackupJobArgs{JobID: restore.JobID}, &restore); err != nil {
			t.Fatal(err)
		}
	}
	if restore.State != "succeeded" || restore.Operation != "restore" {
		t.Fatalf("restore job failed: %+v", restore)
	}
	if data, err := os.ReadFile(filepath.Join(target, "config.yaml")); err != nil || string(data) != config {
		t.Fatalf("restored config: %s %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(target, "agent")); !os.IsNotExist(err) {
		t.Fatal("runtime Agent token was backed up")
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
	var options agent.KernelOptionsResult
	if err := client.Call(context.Background(), "kernel-options", nil, &options); err != nil || options.Overrides.IPv6 != nil {
		t.Fatalf("headless inherited options: %+v %v", options, err)
	}
	enabled := true
	if err := client.Call(context.Background(), "kernel-option", agent.KernelOptionArgs{Name: "ipv6", BoolValue: &enabled}, &options); err != nil || options.Overrides.IPv6 == nil || !*options.Overrides.IPv6 || options.Effective == nil || !options.Effective.IPv6 {
		t.Fatalf("headless option update: %+v %v", options, err)
	}
	options = agent.KernelOptionsResult{}
	if err := client.Call(context.Background(), "kernel-option", agent.KernelOptionArgs{Name: "ipv6", Inherit: true}, &options); err != nil || options.Overrides.IPv6 != nil {
		t.Fatalf("headless option inheritance: %+v %v", options, err)
	}
	invalidPort := 0
	if err := client.Call(context.Background(), "kernel-option", agent.KernelOptionArgs{Name: "mixed-port", PortValue: &invalidPort}, &options); err == nil {
		t.Fatal("headless Agent accepted disabled mixed port")
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
	var history agent.RewriteHistory
	if err := client.Call(context.Background(), "rewrite-history", nil, &history); err != nil || len(history.Entries) == 0 {
		t.Fatalf("missing rewrite history: %+v %v", history, err)
	}
	oldRevision := history.Entries[0].Revision
	var rollback agent.Preview
	if err := client.Call(context.Background(), "rollback-preview", agent.RollbackArgs{Revision: &oldRevision, Scope: "global"}, &rollback); err != nil || rollback.ProposalID == "" {
		t.Fatalf("rollback preview failed: %+v %v", rollback, err)
	}
	if err := client.Call(context.Background(), "apply", agent.ApplyArgs{ProposalID: rollback.ProposalID}, &applied); err != nil {
		t.Fatal(err)
	}
	if err := client.Call(context.Background(), "status", nil, &status); err != nil || len(status.Overrides.Global.Prepend) != 0 {
		t.Fatalf("rollback did not restore previous state: %+v %v", status, err)
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
	var lastUserAgent atomic.Value
	var lastPath atomic.Value
	lastUserAgent.Store("")
	lastPath.Store("")
	started, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscription" && r.URL.Path != "/replacement" && r.URL.Path != "/invalid" {
			http.NotFound(w, r)
			return
		}
		lastPath.Store(r.URL.Path)
		lastUserAgent.Store(r.Header.Get("User-Agent"))
		if r.URL.Path == "/invalid" {
			_, _ = w.Write([]byte("invalid: ["))
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
	var imported profile.File
	var catalogErr error
	a.runOnMain(func() { imported, catalogErr = a.profiles.Load() })
	if catalogErr != nil || len(imported.Items) != 1 || imported.Items[0].UID != first.ProfileID || imported.Items[0].Name != "first" || imported.Items[0].Option.AllowAutoUpdate {
		t.Fatal("imported profile metadata was not committed with the new entry")
	}
	var list agent.ProfileList
	if err := client.Call(context.Background(), "profiles", nil, &list); err != nil || len(list.Profiles) != 1 || !list.Profiles[0].Active {
		t.Fatalf("profiles: %+v %v", list, err)
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), server.URL) {
		t.Fatal("profile list leaked URL")
	}
	var settings agent.ProfileSettings
	if err := client.Call(context.Background(), "profile-settings", agent.ProfileArgs{ProfileID: first.ProfileID}, &settings); err != nil || settings.Name != "first" || !settings.Active {
		t.Fatalf("profile settings: %+v %v", settings, err)
	}
	ua, description, timeout := "NetFlow-agent-test", "description", 25
	if err := client.Call(context.Background(), "profile-settings-set", agent.ProfileSettingsPatch{ProfileID: first.ProfileID, UserAgent: &ua, Description: &description, Timeout: &timeout}, &settings); err != nil || settings.UserAgent != ua || settings.Description != description || settings.Timeout != timeout {
		t.Fatalf("profile settings patch: %+v %v", settings, err)
	}
	encoded, _ = json.Marshal(settings)
	if strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), server.URL) {
		t.Fatal("profile settings leaked URL")
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
	if err := client.Call(context.Background(), "profile-settings-set", agent.ProfileSettingsPatch{ProfileID: first.ProfileID, UserAgent: &ua}, &settings); err == nil {
		t.Fatal("settings changed during download")
	}
	var guiEditErr, guiDeleteErr error
	a.runOnMain(func() {
		guiEditErr = a.saveProfileMetadata(ui.ProfileForm{UID: first.ProfileID, Name: "edited"})
		guiDeleteErr = a.DeleteProfile(first.ProfileID)
	})
	if guiEditErr == nil || !strings.Contains(guiEditErr.Error(), "正在更新") || guiDeleteErr == nil || !strings.Contains(guiDeleteErr.Error(), "正在更新") {
		t.Fatalf("GUI changes were not blocked during download: edit=%v delete=%v", guiEditErr, guiDeleteErr)
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
	var inFlight profile.File
	a.runOnMain(func() { inFlight, catalogErr = a.profiles.Load() })
	if catalogErr != nil || len(inFlight.Items) == 0 {
		t.Fatal("profile disappeared during download")
	}
	filePath := filepath.Join(dir, inFlight.Items[0].File)
	original, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	externalEdit := []byte("mode: direct\nrules: ['MATCH,DIRECT']\n")
	if err := os.WriteFile(filePath, externalEdit, 0600); err != nil {
		t.Fatal(err)
	}
	hold.Store(false)
	releaseOnce.Do(func() { close(release) })
	if job = wait(job); job.State != "failed" {
		t.Fatalf("concurrent source edit was not rejected: %+v", job)
	}
	if got, err := os.ReadFile(filePath); err != nil || string(got) != string(externalEdit) {
		t.Fatal("download overwrote external profile edits")
	}
	if err := os.WriteFile(filePath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: first.ProfileID}, &job); err != nil {
		t.Fatal(err)
	}
	if job = wait(job); job.State != "succeeded" {
		t.Fatalf("update after conflict: %+v", job)
	}
	if got := lastUserAgent.Load(); got != ua {
		t.Fatalf("updated user agent not used: %v", got)
	}
	badURL := server.URL + "/invalid?token=synthetic-secret"
	var replaceJob agent.ProfileJob
	if err := client.Call(context.Background(), "profile-url-set", agent.ProfileURLArgs{ProfileID: first.ProfileID, URL: badURL}, &replaceJob); err != nil {
		t.Fatal(err)
	}
	replaceJob = wait(replaceJob)
	encoded, _ = json.Marshal(replaceJob)
	if replaceJob.State != "failed" || strings.Contains(string(encoded), "synthetic-secret") {
		t.Fatalf("invalid URL replacement was not safely rejected: %s", encoded)
	}
	var current profile.File
	a.runOnMain(func() { current, catalogErr = a.profiles.Load() })
	if catalogErr != nil || current.Items[0].URL != url {
		t.Fatal("failed URL replacement changed the catalog")
	}
	newURL := server.URL + "/replacement?token=another-synthetic-secret"
	if err := client.Call(context.Background(), "profile-url-set", agent.ProfileURLArgs{ProfileID: first.ProfileID, URL: newURL}, &replaceJob); err != nil {
		t.Fatal(err)
	}
	replaceJob = wait(replaceJob)
	encoded, _ = json.Marshal(replaceJob)
	if replaceJob.State != "succeeded" || strings.Contains(string(encoded), "another-synthetic-secret") {
		t.Fatalf("URL replacement failed or leaked: %s", encoded)
	}
	a.runOnMain(func() { current, catalogErr = a.profiles.Load() })
	if catalogErr != nil || current.Items[0].URL != newURL {
		t.Fatal("replacement URL was not persisted")
	}
	if err := client.Call(context.Background(), "update-profile", agent.ProfileArgs{ProfileID: first.ProfileID}, &job); err != nil {
		t.Fatal(err)
	}
	if job = wait(job); job.State != "succeeded" || lastPath.Load() != "/replacement" {
		t.Fatal("later update did not use the replacement URL")
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
