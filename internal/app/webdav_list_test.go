package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/webdav"
)

func TestWebDAVListJobReturnsOnlyNamesWithoutCredentials(t *testing.T) {
	name := "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "synthetic-secret" || r.Method != "PROPFIND" {
			t.Error("invalid listing request")
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/%s</d:href><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, name)
	}))
	defer server.Close()
	d := newSerialDispatcher()
	a := &App{dir: t.TempDir(), core: diagnosticsTestEngine{}, dispatch: d.call, webDAVClient: &webdav.Client{HTTP: server.Client()}}
	defer func() { d.close(); a.stopBackup() }()
	var job agent.BackupJob
	var startErr error
	d.call(func() {
		job, startErr = a.beginWebDAVList(agent.WebDAVListArgs{URL: server.URL + "/dav/?token=synthetic-token", User: "user", Password: "synthetic-secret"}, time.Now(), nil)
	})
	if startErr != nil {
		t.Fatal(startErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for job.State == "pending" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		d.call(func() { job, _ = a.getBackupJob(job.JobID, time.Now()) })
	}
	data, _ := json.Marshal(job)
	if job.State != "succeeded" || len(job.RemoteNames) != 1 || job.RemoteNames[0] != name || strings.Contains(string(data), "synthetic-") || strings.Contains(string(data), server.URL) {
		t.Fatalf("unsafe listing result: %s", data)
	}
}
