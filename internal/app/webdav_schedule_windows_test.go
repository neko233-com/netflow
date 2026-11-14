//go:build windows

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/webdav"
)

func TestAutomaticWebDAVQueueRetriesAfterRestartAndRejectsTampering(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "demo" || pass != "synthetic-secret" {
			t.Error("credentials lost")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer server.Close()
	dir, dest := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("rules: []"), 0600); err != nil {
		t.Fatal(err)
	}
	store := appconfig.NewMemory(dir)
	d := newSerialDispatcher()
	a := &App{dir: dir, store: store, core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	defer func() { d.close(); a.stopBackup() }()
	var err error
	d.call(func() {
		if _, err = a.setBackupWebDAV(true); err == nil {
			t.Error("enabled without local schedule")
		}
		_, err = a.setBackupSchedule(true, dest, 1, time.Now().Add(-2*time.Hour))
		if err != nil {
			return
		}
		if _, err = a.setBackupWebDAV(true); err == nil {
			t.Error("enabled without protected credentials")
		}
		err = a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: server.URL + "/dav", User: "demo", Password: "synthetic-secret"})
		if err != nil {
			return
		}
		_, err = a.setBackupWebDAV(true)
		if err == nil {
			a.autoBackupOne(time.Now())
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	wait := func() {
		t.Helper()
		limit := time.Now().Add(10 * time.Second)
		for {
			var busy bool
			d.call(func() { busy = a.backupBusy || a.backupScanBusy })
			if !busy {
				return
			}
			if time.Now().After(limit) {
				t.Fatal("job timed out")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait()
	state, _, err := a.readBackupSchedule()
	if err != nil || len(state.WebDAVQueue) != 1 {
		t.Fatalf("queue missing: %+v %v", state, err)
	}
	if calls.Load() != 0 {
		t.Fatal("uploaded before scheduler selected queued job")
	}
	d.call(func() { a.autoBackupOne(time.Now()) })
	wait()
	state, _, err = a.readBackupSchedule()
	if err != nil || len(state.WebDAVQueue) != 1 || calls.Load() != 1 {
		t.Fatal("failed upload did not remain queued", err)
	}
	var savedSettings = a.settings
	d.call(func() {
		a = &App{dir: dir, store: store, settings: savedSettings, core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	})
	archive := filepath.Join(dest, state.WebDAVQueue[0].Name)
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	d.call(func() { a.autoBackupOne(time.Now()) })
	wait()
	if calls.Load() != 1 {
		t.Fatal("tampered archive uploaded")
	}
	if err := os.WriteFile(archive, original, 0600); err != nil {
		t.Fatal(err)
	}
	d.call(func() {
		a.backupWebDAVRetry = time.Time{}
		a.backupCheckAfter = time.Time{}
		a.autoBackupOne(time.Now())
	})
	wait()
	state, _, err = a.readBackupSchedule()
	if err != nil || len(state.WebDAVQueue) != 0 || calls.Load() != 2 {
		t.Fatalf("retry did not drain queue: %v %d", err, calls.Load())
	}
	data, err := os.ReadFile(filepath.Join(dir, scheduleFile))
	if err != nil || strings.Contains(string(data), "synthetic-secret") || strings.Contains(string(data), server.URL) {
		t.Fatal("schedule exposed WebDAV credentials")
	}
}

func TestAutomaticWebDAVStopsWhenCredentialsChange(t *testing.T) {
	dir, dest := t.TempDir(), t.TempDir()
	store := appconfig.NewMemory(dir)
	a := &App{dir: dir, store: store}
	if _, err := a.setBackupSchedule(true, dest, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: "https://one.invalid/dav", Password: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.setBackupWebDAV(true); err != nil {
		t.Fatal(err)
	}
	state, _, err := a.readBackupSchedule()
	if err != nil {
		t.Fatal(err)
	}
	state.WebDAVQueue = []queuedWebDAVBackup{{Name: "netflow-auto-queued.zip", Digest: strings.Repeat("0", 64)}}
	_, raw, err := a.readBackupSchedule()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.writeBackupState(state, raw); err != nil {
		t.Fatal(err)
	}
	if err := a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: "https://two.invalid/dav", Password: "two"}); err != nil {
		t.Fatal(err)
	}
	current, raw, err := a.readBackupSchedule()
	if err != nil {
		t.Fatal(err)
	}
	a.startScheduledWebDAV(current, raw, time.Now())
	if a.backupBusy || a.backupWebDAVError == "" {
		t.Fatal("changed credentials allowed an unattended upload")
	}
	current, _, err = a.readBackupSchedule()
	if err != nil || len(current.WebDAVQueue) != 1 {
		t.Fatal("stopped upload lost queued backup", err)
	}
	binding, err := a.webDAVScheduleBinding()
	if err != nil || binding == state.WebDAVBinding {
		t.Fatal("changed credentials still match binding", err)
	}
	if _, err := a.setBackupWebDAV(false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.setBackupWebDAV(true); err != nil {
		t.Fatal(err)
	}
	updated, _, err := a.readBackupSchedule()
	if err != nil || updated.WebDAVBinding != binding {
		t.Fatal("explicit re-enable did not bind new settings", err)
	}
}

func TestAutomaticWebDAVDrainsWhileLocalBackupIsInBackoff(t *testing.T) {
	var uploads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		uploads.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	dir, dest := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("rules: []"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dest, "netflow-auto-pending.zip")
	if _, err := backup.ExportRunning(context.Background(), dir, archive); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	for i := 1; i < scheduleLimit; i++ {
		if err := os.WriteFile(filepath.Join(dest, fmt.Sprintf("netflow-auto-%02d.zip", i)), []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store := appconfig.NewMemory(dir)
	d := newSerialDispatcher()
	a := &App{dir: dir, store: store, core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	defer func() { d.close(); a.stopBackup() }()
	var setupErr error
	d.call(func() {
		_, setupErr = a.setBackupSchedule(true, dest, 1, time.Now().Add(-2*time.Hour))
		if setupErr != nil {
			return
		}
		setupErr = a.saveWebDAVConfig(agent.WebDAVConfigArgs{URL: server.URL})
		if setupErr != nil {
			return
		}
		_, setupErr = a.setBackupWebDAV(true)
		if setupErr != nil {
			return
		}
		state, raw, err := a.readBackupSchedule()
		if err != nil {
			setupErr = err
			return
		}
		state.WebDAVQueue = []queuedWebDAVBackup{{Name: filepath.Base(archive), Digest: hex.EncodeToString(digest[:])}}
		setupErr = a.writeBackupState(state, raw)
		if setupErr == nil {
			a.autoBackupOne(time.Now())
		}
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	wait := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var busy bool
			d.call(func() { busy = a.backupBusy })
			if !busy {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("job timed out")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait()
	var retry time.Time
	d.call(func() { retry = a.backupRetry })
	if retry.IsZero() {
		t.Fatal("local capacity did not enter backoff")
	}
	now := time.Now()
	var next time.Time
	d.call(func() {
		a.backupWebDAVRetry = now.Add(30 * time.Second)
		a.autoBackupOne(now)
		next = a.backupCheckAfter
	})
	if !next.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("did not honor earliest retry: %v", next)
	}
	d.call(func() { a.autoBackupOne(now.Add(29 * time.Second)) })
	if uploads.Load() != 0 {
		t.Fatal("remote retry ran prematurely")
	}
	d.call(func() { a.autoBackupOne(now.Add(31 * time.Second)) })
	wait()
	state, _, err := a.readBackupSchedule()
	if err != nil || len(state.WebDAVQueue) != 0 || uploads.Load() != 1 {
		t.Fatalf("local backoff starved pending upload: queue=%d uploads=%d err=%v", len(state.WebDAVQueue), uploads.Load(), err)
	}
	files, err := os.ReadDir(dest)
	if err != nil || len(files) != scheduleLimit {
		t.Fatal("automatic backup deleted existing archives", err)
	}
}
