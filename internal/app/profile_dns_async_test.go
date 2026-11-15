package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIDNSChangeRemainsResponsiveAndRollsBack(t *testing.T) {
	for _, scenario := range []string{"cancel", "success", "external-catalog"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enteredOnce, cancelOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
					cancelOnce.Do(func() { close(canceled) })
					return
				case <-release:
				}
				_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
			}))
			defer provider.Close()
			defer unblock()
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			path := filepath.Join(dir, "source.yaml")
			if err := os.WriteFile(path, []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			if err := a.ImportLocal(path); err != nil {
				t.Fatal(err)
			}
			id := a.core.ProfileID()
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/dns.yaml, interval: 3600, health-check: {enable: false}}\n"
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(next), 0600); err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			d.call(func() { a.setProfileDNSAsync(id, true, "enable: false\n", func(err error) { result <- err }) })
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("provider did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			if scenario == "external-catalog" {
				if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte("external edit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "success" {
				unblock()
			} else {
				d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("provider did not cancel")
				}
				unblock()
			}
			var resultErr error
			select {
			case resultErr = <-result:
			case <-time.After(15 * time.Second):
				t.Fatal("transaction did not finish")
			}
			if (scenario == "success") != (resultErr == nil) {
				t.Fatalf("result: %v", resultErr)
			}
			if scenario == "external-catalog" {
				data, _ := os.ReadFile(filepath.Join(dir, "profiles.json"))
				if string(data) != "external edit" || !strings.Contains(resultErr.Error(), "恢复原 DNS 设置失败") {
					t.Fatalf("conflict lost: %q %v", data, resultErr)
				}
			} else {
				catalog, err := a.profiles.Load()
				if err != nil {
					t.Fatal(err)
				}
				if len(catalog.Items) != 1 || catalog.Items[0].Option.DNSEnabled != (scenario == "success") {
					t.Fatal("DNS setting not committed or restored")
				}
			}
		})
	}
}
