package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalStopInterruptsInitialProvider(t *testing.T) {
	for _, initialStart := range []bool{true, false} {
		t.Run(fmt.Sprintf("initialStart=%v", initialStart), func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			engine := New()
			defer engine.Stop()
			if !initialStart {
				if err := engine.Start(dir); err != nil {
					t.Fatal(err)
				}
			}
			config := base + "proxy-providers:\n  uncached: {type: http, url: '" + server.URL + "', path: providers/new.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if initialStart {
					done <- engine.Start(dir)
				} else {
					done <- engine.Reload()
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("initial download did not start")
			}
			stopped := make(chan error, 1)
			go func() { stopped <- engine.Stop() }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("local stop waited for initial provider")
			}
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("initial provider was not canceled")
			}
			if err := <-done; err == nil {
				t.Fatal("interrupted apply reported success")
			}
			if engine.Status().Running {
				t.Fatal("kernel still running")
			}
			if err := os.WriteFile(path, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			if err := engine.Start(dir); err != nil {
				t.Fatalf("restart after stop: %v", err)
			}
		})
	}
}
