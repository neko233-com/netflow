package core

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/ui"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/tunnel"

	mygoui "github.com/egoist/mygo/ui"
)

// These tests drive mihomo's process-wide singleton. Do not call t.Parallel.

func TestStartStopDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := writeDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mixed-port: 7897", "socks-port: 7898", "port: 7899", "MATCH,DIRECT"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("default config missing %q", want)
		}
	}
	port := freePort(t)
	data = []byte(strings.ReplaceAll(string(data), "mixed-port: 7897", fmt.Sprintf("mixed-port: %d", port)))
	data = []byte(strings.ReplaceAll(string(data), "socks-port: 7898", "socks-port: 0"))
	data = []byte(strings.ReplaceAll(string(data), "port: 7899", "port: 0"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })

	data, err = os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		fmt.Sprintf("mixed-port: %d", port),
		"MATCH,DIRECT",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("config missing %q\n%s", want, text)
		}
	}

	st := c.Status()
	if !st.Running {
		t.Fatal("status running = false")
	}
	if st.Version != EmbeddedVersion {
		t.Fatalf("version %q, want %s", st.Version, EmbeddedVersion)
	}
	if st.MixedPort != port {
		t.Fatalf("mixed port %d, want %d", st.MixedPort, port)
	}
	if st.ConfigDir != dir {
		t.Fatalf("config dir %q, want %q", st.ConfigDir, dir)
	}
	if st.Mode != "rule" {
		t.Fatalf("mode %q, want rule", st.Mode)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListen(addr); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if waitListen(addr) == nil {
		t.Fatal("mixed port still listening after Stop")
	}
	if c.Status().Running {
		t.Fatal("status still running")
	}
}

func TestStartTwice(t *testing.T) {
	dir := t.TempDir()
	config := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nrules:\n  - MATCH,DIRECT\n", freePort(t))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	if err := c.Start(dir); err == nil {
		t.Fatal("second Start succeeded")
	}
}

func TestStartReportsOccupiedMixedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dir := t.TempDir()
	port := listener.Addr().(*net.TCPAddr).Port
	config := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nrules:\n  - MATCH,DIRECT\n", port)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err == nil {
		t.Fatal("start succeeded even though the mixed port is occupied")
	}
	if c.Status().Running {
		t.Fatal("failed core is reported as running")
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("existing listener was disturbed: %v", err)
	}
	conn.Close()
}

func TestHTTPSubscriptionDirect(t *testing.T) {
	const body = "proxies:\n  - name: direct-only\n    type: direct\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = ioWrite(w, body)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	mixed := freePort(t)
	api := freePort(t)
	cfg := fmt.Sprintf(`mixed-port: %d
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
external-controller: 127.0.0.1:%d
dns:
  enable: false
proxy-providers:
  sub:
    type: http
    url: %q
    path: providers/sub.yaml
    interval: 86400
    health-check:
      enable: false
proxy-groups:
  - name: PROXY
    type: select
    use:
      - sub
    proxies:
      - DIRECT
rules:
  - MATCH,DIRECT
`, mixed, api, srv.URL)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })

	nodes := c.ProviderProxies("sub")
	if len(nodes) != 1 {
		t.Fatalf("provider proxies %+v, want one DIRECT node", nodes)
	}
	if nodes[0].Name != "direct-only" || nodes[0].Type != "Direct" {
		t.Fatalf("node %+v, want direct-only Direct", nodes[0])
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	nodes = c.ProviderProxies("sub")
	if len(nodes) != 1 || nodes[0].Name != "direct-only" {
		t.Fatalf("after reload %+v", nodes)
	}
	if c.Status().MixedPort != mixed {
		t.Fatalf("mixed port %d, want %d", c.Status().MixedPort, mixed)
	}
	if c.Status().ConfigDir != dir {
		t.Fatalf("config dir %q", c.Status().ConfigDir)
	}
}

func TestSelectWritesSelector(t *testing.T) {
	if err := New().Select("PROXY", "DIRECT"); err == nil {
		t.Fatal("Select on a stopped core succeeded")
	}
	dir := t.TempDir()
	mixed := freePort(t)
	api := freePort(t)
	cfg := fmt.Sprintf(`mixed-port: %d
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
external-controller: 127.0.0.1:%d
dns:
  enable: false
proxies:
  - {name: n1, type: direct}
  - {name: n2, type: direct}
proxy-groups:
  - {name: PROXY, type: select, proxies: [n1, n2, DIRECT]}
rules:
  - MATCH,PROXY
`, mixed, api)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	if err := c.Select("PROXY", "n2"); err != nil {
		t.Fatal(err)
	}
	// Read the in-process registry. CI runs with -race, where the external
	// controller is not listening, so this must not go through HTTP.
	if now := selectorNow(t, "PROXY"); now != "n2" {
		t.Fatalf("kernel selector now %q, want n2", now)
	}
	if err := c.Select("PROXY", "missing"); err == nil {
		t.Fatal("missing node was accepted")
	}
	if now := selectorNow(t, "PROXY"); now != "n2" {
		t.Fatalf("failed select changed kernel now to %q", now)
	}
	if err := c.Select("DIRECT", "n1"); err == nil {
		t.Fatal("DIRECT accepted a selector write")
	}
	// The page lists a node the kernel does not have. The click goes through
	// core.Select; a rejection restores the row and leaves Now at n2.
	clickMissingNode(t, c)
}

func clickMissingNode(t *testing.T, c *Core) {
	t.Helper()
	m := ui.NewModel(ui.HomeState{Running: true, Mode: "rule"})
	m.Profiles = []ui.ProfileItem{{UID: "p1", Name: "sub", Type: "remote", URL: "https://example.com/sub"}}
	m.CurrentProfile = "p1"
	m.Prefs.ProxyColumns = 1
	m.Groups = []ui.ProxyGroup{{
		Name: "PROXY", Type: "select", Now: "n2", Open: true,
		Nodes: []ui.ProxyNode{
			{Name: "n2", Type: "direct", Delay: -1},
			{Name: "ghost", Type: "direct", Delay: -1},
		},
	}}
	m.Home.Node = ui.CurrentNode{Group: "PROXY", Name: "n2", Type: "direct", Delay: -1}
	m.Hooks.SelectProxy = c.Select
	m.Router.Replace("/proxies")
	tt := mygoui.NewTester(m.View, ui.WindowWidth, ui.WindowHeight)
	tt.SetScale(1)
	for i := 0; i < 5 && tt.FramePending(); i++ {
		tt.Advance(time.Second)
	}
	if err := tt.Click("node-PROXY-ghost"); err != nil {
		t.Fatal(err)
	}
	if m.Groups[0].Now != "n2" || m.Home.Node.Name != "n2" {
		t.Fatalf("UI kept the missing node: now %q home %q notice %q", m.Groups[0].Now, m.Home.Node.Name, m.Notice)
	}
	if m.Notice == "" || !tt.HasText(m.Notice) {
		t.Fatalf("missing node notice %q texts %q", m.Notice, tt.Texts())
	}
	if now, err := c.Selected("PROXY"); err != nil || now != "n2" {
		t.Fatalf("kernel Now %q err %v, want n2", now, err)
	}
}

func selectorNow(t *testing.T, group string) string {
	t.Helper()
	p, ok := tunnel.Proxies()[group]
	if !ok || p == nil {
		t.Fatalf("proxy group %s is not in the registry", group)
	}
	sel, ok := p.Adapter().(*outboundgroup.Selector)
	if !ok || sel == nil {
		t.Fatalf("%s adapter %T is not a selector", group, p.Adapter())
	}
	return sel.Now()
}

func TestReloadWhenStopped(t *testing.T) {
	if err := New().Reload(); err == nil {
		t.Fatal("Reload on a stopped core succeeded")
	}
}

func TestProviderUpdatesRejectChangedProfileBeforeLookup(t *testing.T) {
	c := New()
	c.SetProfileID("new")
	for _, update := range []func(string, string) error{c.UpdateProxyProviderForProfile, c.UpdateRuleProviderForProfile} {
		if err := update("provider", "old"); err == nil || !strings.Contains(err.Error(), "profile changed") {
			t.Fatalf("changed profile accepted: %v", err)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	var held []net.PacketConn
	defer func() {
		for _, socket := range held {
			_ = socket.Close()
		}
	}()
	for i := 0; i < 1024; i++ {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = tcp.Close()
			_ = udp.Close()
			return port
		}
		held = append(held, udp)
	}
	t.Fatal("could not reserve a TCP and UDP port")
	return 0
}

func waitListen(addr string) error {
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		time.Sleep(30 * time.Millisecond)
	}
	return fmt.Errorf("dial %s: %w", addr, last)
}

func ioWrite(w http.ResponseWriter, s string) (int, error) {
	return w.Write([]byte(s))
}
