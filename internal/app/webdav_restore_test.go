package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/webdav"
)

func TestWebDAVRestoreValidatesBeforeCreatingDestinationAndCleansDownload(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid"}[corrupt], func(t *testing.T) {
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "config.yaml"), []byte("rules: []"), 0600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "backup.zip")
			if _, err := backup.Export(source, archive); err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				payload[0] ^= 1
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
			defer server.Close()
			parent := t.TempDir()
			dest := filepath.Join(parent, "restored")
			d := newSerialDispatcher()
			a := &App{dir: t.TempDir(), core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
			defer func() { d.close(); a.stopBackup() }()
			args := agent.WebDAVRestoreArgs{Destination: dest, URL: server.URL, RemoteName: "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"}
			var job agent.BackupJob
			var startErr error
			d.call(func() { job, startErr = a.beginWebDAVRestore(args, time.Now(), nil) })
			if startErr != nil {
				t.Fatal(startErr)
			}
			deadline := time.Now().Add(10 * time.Second)
			for job.State == "pending" && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
				d.call(func() { job, _ = a.getBackupJob(job.JobID, time.Now()) })
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				if job.State != "failed" || len(entries) != 0 {
					t.Fatalf("invalid archive created files: %+v %v", job, entries)
				}
			} else {
				body, err := os.ReadFile(filepath.Join(dest, "config.yaml"))
				if job.State != "succeeded" || len(entries) != 1 || err != nil || string(body) != "rules: []" {
					t.Fatalf("restore failed: %+v %v", job, err)
				}
			}
		})
	}
}

func TestWebDAVRestoreRejectsExistingAndActiveDestinations(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	config, parent := t.TempDir(), t.TempDir()
	dest := filepath.Join(parent, "existing")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dest, "keep")
	if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	d := newSerialDispatcher()
	a := &App{dir: config, core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	defer func() { d.close(); a.stopBackup() }()
	args := agent.WebDAVRestoreArgs{Destination: filepath.Join(config, "inside"), URL: server.URL, RemoteName: "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"}
	if _, err := a.beginWebDAVRestore(args, time.Now(), nil); err == nil {
		t.Fatal("accepted active configuration destination")
	}
	args.Destination = dest
	var job agent.BackupJob
	var err error
	d.call(func() { job, err = a.beginWebDAVRestore(args, time.Now(), nil) })
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for job.State == "pending" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		d.call(func() { job, _ = a.getBackupJob(job.JobID, time.Now()) })
	}
	body, err := os.ReadFile(marker)
	if job.State != "failed" || calls.Load() != 0 || err != nil || string(body) != "original" {
		t.Fatal("existing destination changed or network was contacted")
	}
}
