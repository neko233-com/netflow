package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestDelayIsCanceledOnCoreReloadAndStop(t *testing.T) {
	for _, action := range []string{"reload", "stop"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			c := New()
			if err := c.Start(dir); err != nil {
				t.Fatal(err)
			}
			defer c.Stop()
			entered, release := make(chan struct{}), make(chan struct{})
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					close(entered)
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			defer close(release)
			result := make(chan error, 1)
			go func() { _, err := c.TestDelay("", "DIRECT", srv.URL, 30*time.Second); result <- err }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("probe did not reach server")
			}
			var err error
			if action == "reload" {
				err = c.Reload()
			} else {
				err = c.Stop()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("probe was not canceled: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("probe stayed active after core transition")
			}
			if action == "stop" {
				if err := c.Start(dir); err != nil {
					t.Fatal(err)
				}
			}
			if ms, err := c.TestDelay("", "DIRECT", srv.URL, 3*time.Second); err != nil || ms < 1 {
				t.Fatalf("new probe failed: %d %v", ms, err)
			}
		})
	}
}
