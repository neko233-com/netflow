package app

import (
	"bytes"
	"encoding/json"
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
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/webdav"
)

func TestWebDAVUploadJobRedactsCredentialsAndDetectsMutation(t *testing.T) {
	for _, mutate := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "changed"}[mutate], func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(t.TempDir(), "archive.zip")
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "config.yaml"), []byte("rules: []"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := backup.Export(source, archive); err != nil {
				t.Fatal(err)
			}
			archiveBytes, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				body, err := io.ReadAll(r.Body)
				if !ok || user != "demo" || password != "synthetic-secret" || !bytes.Equal(body, archiveBytes) || err != nil {
					t.Error("incorrect upload request")
				}
				if mutate {
					changed := append([]byte(nil), archiveBytes...)
					changed[0] ^= 1
					if err := os.WriteFile(archive, changed, 0600); err != nil {
						t.Error(err)
					}
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()
			d := newSerialDispatcher()
			client := &webdav.Client{HTTP: server.Client()}
			a := &App{dir: dir, core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: client}
			defer func() { d.close(); a.stopBackup() }()
			args := agent.WebDAVUploadArgs{Archive: archive, URL: server.URL + "/?token=synthetic-token", User: "demo", Password: "synthetic-secret"}
			var job agent.BackupJob
			var startErr error
			d.call(func() { job, startErr = a.beginWebDAVUpload(args, time.Now(), nil) })
			if startErr != nil {
				t.Fatal(startErr)
			}
			deadline := time.Now().Add(10 * time.Second)
			for job.State == "pending" && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
				d.call(func() { job, _ = a.getBackupJob(job.JobID, time.Now()) })
			}
			if job.RemoteName == "" || (!mutate && job.State != "succeeded") || (mutate && job.State != "failed") {
				t.Fatalf("unexpected job result: %+v", job)
			}
			data, _ := json.Marshal(job)
			if strings.Contains(string(data), "synthetic-secret") || strings.Contains(string(data), "synthetic-token") || strings.Contains(string(data), server.URL) {
				t.Fatal("job result exposed credentials")
			}
		})
	}
}

func TestWebDAVRejectsInvalidArchiveBeforeConnecting(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusCreated) }))
	defer server.Close()
	d := newSerialDispatcher()
	a := &App{dir: t.TempDir(), core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	defer func() { d.close(); a.stopBackup() }()
	archive := filepath.Join(t.TempDir(), "invalid.zip")
	if err := os.WriteFile(archive, []byte("private unrelated data"), 0600); err != nil {
		t.Fatal(err)
	}
	var job agent.BackupJob
	var startErr error
	d.call(func() {
		job, startErr = a.beginWebDAVUpload(agent.WebDAVUploadArgs{Archive: archive, URL: server.URL}, time.Now(), nil)
	})
	if startErr != nil {
		t.Fatal(startErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for job.State == "pending" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		d.call(func() { job, _ = a.getBackupJob(job.JobID, time.Now()) })
	}
	if job.State != "failed" || calls.Load() != 0 {
		t.Fatalf("invalid archive reached server: %+v", job)
	}
}
