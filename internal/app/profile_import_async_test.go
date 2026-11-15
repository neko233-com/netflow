package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestFirstProfileImportReloadIsCancelable(t *testing.T) {
	for _, scenario := range []string{"remote-cancel", "local-cancel", "success", "external-profile", "agent-external-profile", "external-catalog", "external-config"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, release := make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
				case <-release:
					_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
				}
			}))
			defer provider.Close()
			defer unblock()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/import.yaml, interval: 3600, health-check: {enable: false}}\n"
			sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, next) }))
			defer sub.Close()
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			idResult := make(chan string, 1)
			if scenario == "local-cancel" {
				file := filepath.Join(dir, "input.yaml")
				if err := os.WriteFile(file, []byte(next), 0600); err != nil {
					t.Fatal(err)
				}
				d.call(func() { a.importLocalAsync(file, func(err error) { result <- err }) })
			} else if scenario == "agent-external-profile" {
				d.call(func() {
					a.createProfileWithResult(ui.ProfileForm{URL: sub.URL, Timeout: 20, Interval: 1440}, func(uid string, err error) { idResult <- uid; result <- err })
				})
			} else {
				d.call(func() { a.importURLAsync(sub.URL, func(err error) { result <- err }) })
			}
			select {
			case <-entered:
			case <-time.After(15 * time.Second):
				t.Fatal("provider did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			catalog, err := profile.NewStore(dir).Load()
			if err != nil || len(catalog.Items) != 1 {
				t.Fatalf("staged catalog: %+v %v", catalog, err)
			}
			switch scenario {
			case "external-profile", "agent-external-profile":
				if err := os.WriteFile(filepath.Join(dir, catalog.Items[0].File), []byte("rules: ['MATCH,REJECT']\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "external-catalog":
				if err := a.profiles.UpdateMetadata(catalog.Current, "external", "", nil); err != nil {
					t.Fatal(err)
				}
			case "external-config":
				if err := os.WriteFile(configPath, []byte("external edit\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "success" {
				unblock()
			} else {
				d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
			}
			select {
			case err = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("import did not finish")
			}
			if (err == nil) != (scenario == "success") {
				t.Fatalf("import error: %v", err)
			}
			d.call(func() {}) // Wait for completion callback and barrier cleanup.
			catalog, err = a.profiles.Load()
			if err != nil {
				t.Fatal(err)
			}
			keep := scenario == "success" || scenario == "external-profile" || scenario == "agent-external-profile" || scenario == "external-catalog" || scenario == "external-config"
			if (len(catalog.Items) == 1) != keep {
				t.Fatalf("catalog after %s: %+v", scenario, catalog)
			}
			if !keep && catalog.Current != "" {
				t.Fatalf("current after rollback: %s", catalog.Current)
			}
			if scenario != "success" && scenario != "external-config" {
				after, e := os.ReadFile(configPath)
				if e != nil || !bytes.Equal(before, after) {
					t.Fatalf("config not restored: %v", e)
				}
			}
			if scenario == "external-profile" || scenario == "agent-external-profile" {
				data, e := os.ReadFile(filepath.Join(dir, catalog.Items[0].File))
				if e != nil || string(data) != "rules: ['MATCH,REJECT']\n" {
					t.Fatal("external profile edit lost")
				}
			}
			if scenario == "agent-external-profile" && <-idResult != catalog.Items[0].UID {
				t.Fatal("partial import identifier was lost")
			}
			if scenario == "external-catalog" && catalog.Items[0].Name != "external" {
				t.Fatal("external catalog edit lost")
			}
			if scenario == "external-config" {
				data, _ := os.ReadFile(configPath)
				if string(data) != "external edit\n" {
					t.Fatal("external config edit lost")
				}
			}
		})
	}
}

func TestHeadlessShutdownRestoresPendingFirstImport(t *testing.T) {
	t.Setenv("CI", "1")
	entered := make(chan struct{})
	var once sync.Once
	provider := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-r.Context().Done()
	}))
	defer provider.Close()
	base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
	next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/import.yaml, interval: 3600, health-check: {enable: false}}\n"
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, next) }))
	defer sub.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, finished := make(chan bool, 1), make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(v bool) { ready <- v }}) }()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatal(err)
	case <-time.After(20 * time.Second):
		t.Fatal("not ready")
	}
	before, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
	var job agent.ProfileJob
	if err := client.Call(context.Background(), "import-profile", agent.ProfileImportArgs{URL: sub.URL}, &job); err != nil || job.JobID == "" {
		t.Fatalf("job: %+v %v", job, err)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("provider did not start")
	}
	var shutdown agent.ActionResult
	if err := client.Call(context.Background(), "shutdown", nil, &shutdown); err != nil || !shutdown.OK {
		t.Fatalf("shutdown: %+v %v", shutdown, err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("shutdown stalled")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("config not restored", err)
	}
	catalog, err := profile.NewStore(dir).Load()
	if err != nil || len(catalog.Items) != 0 || catalog.Current != "" {
		t.Fatalf("catalog not restored: %+v %v", catalog, err)
	}
}
