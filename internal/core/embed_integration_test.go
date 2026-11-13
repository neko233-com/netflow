//go:build integration

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	mprofile "github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel"
)

// mihomo keeps HomeDir, the external controller, and cache.db in process
// globals. These tests must not call t.Parallel. The mutex also covers
// `go test` without -p 1.
//
// Window-free Profiles and Proxies clicks live in internal/ui and
// internal/app. This file only boots the embedded core.
//
// Under -race the tests skip. Two M1 issues stack: startExternalController
// does not listen, and hub.Parse calls log.SetLevel while mihomo finalizers
// call log.Debugln, which the race detector reports. Run
// `go test -tags=integration` without -race for the HTTP assertions.

var mihomoMu sync.Mutex

func lockMihomo(t *testing.T) {
	t.Helper()
	if !externalControllerEnabled {
		t.Skip("skipping mihomo embed smoke under -race: the external controller does not listen, and hub.Parse races in mihomo's logger (known M1 issue)")
	}
	mihomoMu.Lock()
	t.Cleanup(func() {
		releaseListeners()
		mprofile.StoreSelected.Store(false)
		mihomoMu.Unlock()
	})
}

const directConfig = `mixed-port: 0
socks-port: 0
port: 0
redir-port: 0
tproxy-port: 0
allow-lan: false
mode: rule
log-level: error
ipv6: false
find-process-mode: off
geo-auto-update: false
unified-delay: false
external-controller: 127.0.0.1:%d
profile:
  store-selected: %t
dns:
  enable: false
proxies:
  - name: n1
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
      - n1
rules:
  - MATCH,PROXY
`

func bootDirect(t *testing.T, storeSelected bool) (addr string, raw []byte) {
	t.Helper()
	port := freePort(t)
	raw = []byte(fmt.Sprintf(directConfig, port, storeSelected))
	dir := t.TempDir()
	C.SetHomeDir(dir)
	C.SetConfig(filepath.Join(dir, "config.yaml"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(C.Path.Config(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
	route.SetEmbedMode(true)
	if err := hub.Parse(suppressExternalController(raw)); err != nil {
		t.Fatalf("hub.Parse: %v", err)
	}
	addr = fmt.Sprintf("127.0.0.1:%d", port)
	startExternalController(addr, "", false)
	if err := waitListen(addr); err != nil {
		t.Fatal(err)
	}
	return addr, raw
}

func reparseDirect(t *testing.T, raw []byte, addr string) {
	t.Helper()
	if err := hub.Parse(suppressExternalController(raw)); err != nil {
		t.Fatalf("hub.Parse: %v", err)
	}
	startExternalController(addr, "", false)
	if err := waitListen(addr); err != nil {
		t.Fatal(err)
	}
}

func TestHubParseDirectVersion(t *testing.T) {
	lockMihomo(t)
	addr, _ := bootDirect(t, false)
	if Version() == "" {
		t.Fatal("version empty after hub.Parse")
	}
	n1, ok := tunnel.Proxies()["n1"]
	if !ok || n1 == nil || n1.Type().String() != "Direct" {
		t.Fatalf("n1 %#v, want a direct proxy", n1)
	}
	if now := proxyNow(t, "PROXY"); now != "DIRECT" {
		t.Fatalf("initial selection %q, want DIRECT", now)
	}

	resp, err := http.Get("http://" + addr + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /version %d %s", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("version json: %v body %s", err, body)
	}
	got, _ := payload["version"].(string)
	if got == "" {
		t.Fatalf("version payload %#v", payload)
	}
	if _, ok := payload["meta"]; !ok {
		t.Fatalf("version payload missing meta: %#v", payload)
	}
	// The controller reports C.Version. That string is not required to
	// equal the module tag, so this checks the field rather than a literal.
	if got != Version() {
		t.Fatalf("controller version %q, core Version %q", got, Version())
	}
}

func TestSelectPersistAcrossApply(t *testing.T) {
	lockMihomo(t)
	addr, raw := bootDirect(t, true)

	// Pin DIRECT first. cache.db is a process singleton, so a previous
	// test may already have stored PROXY. Restoring that value would make
	// a failed write look like a successful one.
	putSelect(t, addr, "PROXY", "DIRECT")
	reparseDirect(t, raw, addr)
	if now := proxyNow(t, "PROXY"); now != "DIRECT" {
		t.Fatalf("after reset now %q, want DIRECT", now)
	}

	putSelect(t, addr, "PROXY", "n1")
	selected := cachefile.Cache().SelectedMap()
	if selected["PROXY"] != "n1" {
		t.Fatalf("cache %#v, want PROXY=n1", selected)
	}
	reparseDirect(t, raw, addr)
	if now := proxyNow(t, "PROXY"); now != "n1" {
		t.Fatalf("after apply now %q, want n1", now)
	}
	if got := proxyNowHTTP(t, addr, "PROXY"); got != "n1" {
		t.Fatalf("GET /proxies/PROXY now %q, want n1", got)
	}
}

func TestDelayDirectAgainstLocal204(t *testing.T) {
	lockMihomo(t)
	addr, _ := bootDirect(t, true)
	putSelect(t, addr, "PROXY", "n1")
	if cachefile.Cache().SelectedMap()["PROXY"] != "n1" {
		t.Fatalf("selected cache %#v", cachefile.Cache().SelectedMap())
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	if delay := proxyDelayHTTP(t, addr, "n1", srv.URL); delay <= 0 {
		t.Fatalf("delay %d, want a positive finite number", delay)
	}
}

func putSelect(t *testing.T, addr, group, node string) {
	t.Helper()
	endpoint := "http://" + addr + "/proxies/" + url.PathEscape(group)
	req, err := http.NewRequest(http.MethodPut, endpoint, strings.NewReader(fmt.Sprintf(`{"name":%q}`, node)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT %s %d %s", group, resp.StatusCode, body)
	}
}

func proxyNow(t *testing.T, name string) string {
	t.Helper()
	p, ok := tunnel.Proxies()[name]
	if !ok || p == nil {
		t.Fatalf("proxy %s missing", name)
	}
	nower, ok := p.Adapter().(interface{ Now() string })
	if !ok {
		t.Fatalf("%s is not a group", name)
	}
	return nower.Now()
}

func proxyNowHTTP(t *testing.T, addr, name string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/proxies/" + url.PathEscape(name))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxies/%s %d %s", name, resp.StatusCode, body)
	}
	var payload struct {
		Now string `json:"now"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Now
}

func proxyDelayHTTP(t *testing.T, addr, name, target string) int {
	t.Helper()
	q := url.Values{}
	q.Set("url", target)
	q.Set("timeout", "3000")
	endpoint := "http://" + addr + "/proxies/" + url.PathEscape(name) + "/delay?" + q.Encode()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET delay %d %s", resp.StatusCode, body)
	}
	var payload struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("delay json: %v body %s", err, body)
	}
	return payload.Delay
}
