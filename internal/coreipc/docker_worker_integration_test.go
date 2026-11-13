//go:build linux && integration

package coreipc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/miekg/dns"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/tun"
)

func dockerState(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip: %s: %v", out, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestDockerWorkerHelper(t *testing.T) {
	if os.Getenv("NETFLOW_DOCKER_WORKER_CHILD") != "1" {
		return
	}
	pipe := os.NewFile(3, "parent-kernel-pipe")
	if pipe == nil {
		t.Fatal("missing parent pipe")
	}
	if err := NewWorker().Serve(pipe); err != nil {
		t.Fatal(err)
	}
}

// The worker and client are separate processes. Closing the IPC connection
// simulates a GUI crash and must remove the TUN and restore kernel routes.
func TestDockerWorkerCleansTUNAfterDisconnect(t *testing.T) {
	if os.Getenv("NETFLOW_DOCKER_TUN") != "1" {
		t.Skip("requires explicit isolated Docker TUN test")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing TUN test outside Docker")
	}
	routes := dockerState(t, "-4", "route", "show", "table", "all")
	rules := dockerState(t, "-4", "rule", "show")
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent")
	child := os.NewFile(uintptr(fds[1]), "child")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDockerWorkerHelper$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "NETFLOW_DOCKER_WORKER_CHILD=1")
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	nc, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(nc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dir := t.TempDir()
	// Simulate the desktop kernel retaining the original Bolt cache lock.
	lockedCache, err := bbolt.Open(filepath.Join(dir, "cache.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lockedCache.Close()
	peer := os.Getenv("NETFLOW_TUN_TEST_PEER")
	var upstreamCalls atomic.Int32
	var upstreamAddress string
	if peer != "" {
		if ip := net.ParseIP(peer); ip == nil || ip.To4() == nil || ip.IsLoopback() {
			t.Fatal("invalid isolated peer address")
		}
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		upstreamAddress = packet.LocalAddr().String()
		server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
			upstreamCalls.Add(1)
			response := new(dns.Msg)
			response.SetReply(query)
			for _, q := range query.Question {
				if q.Qtype == dns.TypeA && q.Name == "netflow-test.example." {
					response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(peer).To4()})
				}
			}
			_ = w.WriteMsg(response)
		})}
		go func() { _ = server.ActivateAndServe() }()
		defer server.Shutdown()
	}
	config := `mixed-port: 0
port: 0
socks-port: 0
log-level: error
mode: rule
tun:
  enable: false
  device: other-client
  stack: mixed
  auto-route: false
  auto-detect-interface: false
rules:
  - MATCH,DIRECT
`
	if upstreamAddress != "" {
		config += fmt.Sprintf("\ndns:\n  nameserver: ['%s']\n", upstreamAddress)
	}
	composed, err := tun.Compose([]byte(config), true, "netflow-ipc0")
	if err != nil {
		t.Fatal(err)
	}
	stack := "system"
	composed, err = kernelopts.Compose(composed, kernelopts.Options{TUNStack: &stack})
	if err != nil {
		t.Fatal(err)
	}
	config = string(composed)
	if peer != "" {
		config = strings.Replace(config, "MATCH,DIRECT", "MATCH,REJECT", 1)
	}
	if err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err = client.Start(dir); err != nil {
		t.Fatal(err)
	}
	if !client.Status().TUN {
		t.Fatal("worker did not report TUN active")
	}
	if _, err := os.Stat(filepath.Join(dir, "netflow-worker-cache.db")); err != nil {
		t.Fatalf("worker cache missing while original cache is locked: %v", err)
	}
	if _, err = net.InterfaceByName("netflow-ipc0"); err != nil {
		t.Fatalf("missing TUN: %v", err)
	}
	if peer != "" {
		// Force this test destination through TUN; the core's outbound
		// auto-detection must still deliver DIRECT traffic via eth0.
		if out, err := exec.Command("ip", "route", "replace", peer+"/32", "dev", "netflow-ipc0").CombinedOutput(); err != nil {
			t.Fatalf("test route: %s: %v", out, err)
		}
		httpClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		url := "http://" + net.JoinHostPort(peer, "8080") + "/"
		if resp, err := httpClient.Get(url); err == nil {
			resp.Body.Close()
			t.Fatal("REJECT rule did not block TUN traffic")
		}
		config = strings.Replace(config, "MATCH,REJECT", "MATCH,DIRECT", 1)
		if err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if err = client.Reload(); err != nil {
			t.Fatal(err)
		}
		resp, err := httpClient.Get(url)
		if err != nil {
			t.Fatalf("DIRECT TUN traffic: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "OK" {
			t.Fatalf("peer response: %d %q %v", resp.StatusCode, body, err)
		}
		query := new(dns.Msg)
		query.SetQuestion("netflow-test.example.", dns.TypeA)
		dnsClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		answer, _, err := dnsClient.Exchange(query, "8.8.8.8:53")
		if err != nil || len(answer.Answer) == 0 {
			t.Fatalf("TUN DNS hijack: %v", err)
		}
		record, ok := answer.Answer[0].(*dns.A)
		if !ok || !strings.HasPrefix(record.A.String(), "198.18.") {
			t.Fatalf("unexpected fake IP: %+v", answer.Answer)
		}
		fakeIP := record.A.String()
		fakeTransport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(fakeIP, "8080"))
		}}
		fakeClient := &http.Client{Timeout: 5 * time.Second, Transport: fakeTransport}
		fakeResponse, err := fakeClient.Get("http://netflow-test.example:8080/")
		if err != nil {
			t.Fatalf("Fake-IP forwarding: %v", err)
		}
		fakeBody, err := io.ReadAll(fakeResponse.Body)
		fakeResponse.Body.Close()
		fakeTransport.CloseIdleConnections()
		if err != nil || string(fakeBody) != "OK" || upstreamCalls.Load() == 0 {
			t.Fatalf("Fake-IP upstream resolution failed: %q, calls=%d, err=%v", fakeBody, upstreamCalls.Load(), err)
		}
		_, up, down := client.Connections()
		if up == 0 || down == 0 {
			t.Fatalf("TUN traffic counters did not advance: up=%d down=%d", up, down)
		}
	} else {
		t.Log("no isolated peer supplied; TUN traffic forwarding not tested")
	}
	// Exercise all shipped protocol stacks while TUN is active and verify
	// each one forwards to the isolated peer after its listener is recreated.
	for _, stack = range []string{"mixed", "gvisor", "mips", "system"} {
		updated, err := kernelopts.Compose([]byte(config), kernelopts.Options{TUNStack: &stack})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "config.yaml"), updated, 0600); err != nil {
			t.Fatal(err)
		}
		if err = client.Reload(); err != nil {
			t.Fatalf("TUN %s stack reload: %v", stack, err)
		}
		if !client.Status().TUN {
			t.Fatalf("TUN stopped after %s stack change", stack)
		}
		if _, err = net.InterfaceByName("netflow-ipc0"); err != nil {
			t.Fatalf("TUN missing after %s stack change: %v", stack, err)
		}
		if peer != "" {
			if out, err := exec.Command("ip", "route", "replace", peer+"/32", "dev", "netflow-ipc0").CombinedOutput(); err != nil {
				t.Fatalf("%s test route: %s: %v", stack, out, err)
			}
			hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
			resp, err := hc.Get("http://" + net.JoinHostPort(peer, "8080") + "/")
			if err != nil {
				t.Fatalf("%s stack forwarding: %v", stack, err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "OK" {
				t.Fatalf("%s stack response: %q %v", stack, body, err)
			}
		}
	}
	// Leave a delay probe in flight to ensure an abandoned RPC cannot keep
	// the TUN worker alive after the UI pipe disappears.
	probeStarted, releaseProbe := make(chan struct{}), make(chan struct{})
	probeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(probeStarted)
		<-releaseProbe
	}))
	defer probeServer.Close()
	go func() { _, _ = client.TestDelay("", "DIRECT", probeServer.URL, 30*time.Second) }()
	select {
	case <-probeStarted:
	case <-time.After(5 * time.Second):
		close(releaseProbe)
		t.Fatal("delay probe did not start")
	}
	if err = client.Close(); err != nil {
		close(releaseProbe)
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		close(releaseProbe)
		t.Fatal("worker did not exit after disconnect")
	}
	close(releaseProbe)
	if _, err = net.InterfaceByName("netflow-ipc0"); err == nil {
		t.Fatal("orphan TUN after worker exit")
	}
	if got := dockerState(t, "-4", "route", "show", "table", "all"); got != routes {
		t.Fatalf("routes changed after worker exit:\nbefore %s\nafter %s", routes, got)
	}
	if got := dockerState(t, "-4", "rule", "show"); got != rules {
		t.Fatalf("rules changed after worker exit:\nbefore %s\nafter %s", rules, got)
	}
}
