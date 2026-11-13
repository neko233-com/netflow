//go:build windows && integration

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func vmCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	return c
}

func requireDisposableVM(t *testing.T) {
	t.Helper()
	if os.Getenv("NETFLOW_WINDOWS_VM") != "1" || windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("refusing to modify networking outside the filtered Windows validation guest")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	manufacturer, _, err := k.GetStringValue("SystemManufacturer")
	if err != nil || !strings.Contains(strings.ToLower(manufacturer), "qemu") {
		t.Fatalf("refusing non-QEMU machine: %q %v", manufacturer, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := vmCommand(ctx, "wmic.exe", "diskdrive", "get", "model", "/value").CombinedOutput()
	if err != nil {
		t.Fatalf("disk inventory: %s: %v", out, err)
	}
	var disks []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
		if strings.HasPrefix(strings.ToLower(line), "model=") {
			disks = append(disks, strings.ToLower(line))
		}
	}
	if len(disks) != 1 || !strings.Contains(disks[0], "qemu") {
		t.Fatalf("refusing guest without exactly one QEMU disk: %q", disks)
	}
}

func vmNetworkSnapshot() ([]string, map[uint64][]string, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var routes []string
	for _, r := range table.Rows() {
		routes = append(routes, fmt.Sprintf("%d/%d %v %v %d %d", r.InterfaceLuid, r.InterfaceIndex, r.DestinationPrefix, r.NextHop, r.Metric, r.Protocol))
	}
	sort.Strings(routes)
	size := uint32(16384)
	buf := make([]byte, size)
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
	}
	if err != nil {
		return nil, nil, err
	}
	servers := map[uint64][]string{}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != 1 {
			continue
		}
		servers[a.Luid] = []string{}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			servers[a.Luid] = append(servers[a.Luid], d.Address.IP().String())
		}
	}
	return routes, servers, nil
}

func vmHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), err
}

// This test exercises the shipped MSI and real Wintun only inside the isolated,
// single-disk QEMU guest; it must never run against a workstation's routes.
func TestWindowsVMEndToEnd(t *testing.T) {
	requireDisposableVM(t)
	var expected map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("NETFLOW_VM_EXPECTED")), &expected); err != nil || len(expected) != 3 {
		t.Fatal("invalid expected binary hashes")
	}
	msi := os.Getenv("NETFLOW_VM_MSI")
	if !filepath.IsAbs(msi) {
		t.Fatal("missing MSI")
	}
	install := filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "NetFlow")
	matching := true
	for _, name := range []string{"NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"} {
		h, err := vmHash(filepath.Join(install, name))
		if err != nil || h != expected[name] {
			matching = false
		}
	}
	if !matching {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		out, err := vmCommand(ctx, "msiexec.exe", "/i", msi, "/quiet", "/norestart").CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("MSI installation failed: %s: %v", out, err)
		}
	}
	for _, name := range []string{"NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"} {
		h, err := vmHash(filepath.Join(install, name))
		if err != nil || h != expected[name] {
			t.Fatalf("installed %s hash mismatch: %s %v", name, h, err)
		}
	}
	t.Log("MSI installation and installed binary hashes verified")
	agentExe := filepath.Join(install, "netflow-agent.exe")
	verge := t.TempDir()
	if err := os.Mkdir(filepath.Join(verge, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verge, "profiles.yaml"), []byte("current: p1\nitems:\n  - {uid: p1, type: remote, name: Test, url: 'https://example.test/sub', file: p1.yaml}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verge, "profiles", "p1.yaml"), []byte("mixed-port: 0\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	migrationTarget := t.TempDir()
	for _, action := range []string{"migrate-preview", "migrate-import"} {
		c, done := context.WithTimeout(context.Background(), 30*time.Second)
		out, e := vmCommand(c, agentExe, "--config-dir", migrationTarget, action, verge).CombinedOutput()
		done()
		if e != nil {
			t.Fatalf("Verge %s failed: %s: %v", action, out, e)
		}
		var response map[string]any
		if json.Unmarshal(out, &response) != nil {
			t.Fatalf("Verge %s returned invalid JSON: %s", action, out)
		}
		if action == "migrate-import" && response["imported"] != float64(1) {
			t.Fatalf("Verge import result: %s", out)
		}
	}
	t.Log("installed CLI previewed and imported a Clash Verge profile")
	beforeRoutes, beforeDNS, err := vmNetworkSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a := new(dns.Msg)
		a.SetReply(q)
		for _, item := range q.Question {
			if item.Name == "netflow-test.example." && item.Qtype == dns.TypeA {
				a.Answer = append(a.Answer, &dns.A{Hdr: dns.RR_Header{Name: item.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("10.233.42.1").To4()})
			}
		}
		_ = w.WriteMsg(a)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	defer dnsServer.Shutdown()
	dir := t.TempDir()
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\nmode: rule\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: ['%s']\ntun:\n  enable: false\n  stack: system\n  auto-route: true\n  auto-detect-interface: true\nrules:\n  - MATCH,REJECT\n", packet.LocalAddr().String())
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"prefs":"{\"SilentStart\":true}"}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gui := vmCommand(ctx, filepath.Join(install, "NetFlow.exe"))
	gui.Env = append(os.Environ(), "NETFLOW_CONFIG_DIR="+dir, "GOMAXPROCS=1")
	logFile, err := os.Create(filepath.Join(dir, "gui.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	gui.Stdout, gui.Stderr = logFile, logFile
	if err := gui.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gui.Process.Kill(); _ = gui.Wait() }()
	call := func(args ...string) ([]byte, error) {
		c, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		return vmCommand(c, agentExe, append([]string{"--config-dir", dir}, args...)...).CombinedOutput()
	}
	status := func() (agent.Status, error) {
		var s agent.Status
		out, err := call("status")
		if err == nil {
			err = json.Unmarshal(out, &s)
		}
		return s, err
	}
	var s agent.Status
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s, err = status()
		if err == nil && s.Running {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !s.Running {
		data, _ := os.ReadFile(filepath.Join(dir, "gui.log"))
		t.Fatalf("installed GUI did not start agent: %v status=%+v log=%s", err, s, data)
	}
	if out, e := call("tun", "on"); e != nil {
		t.Fatalf("TUN on request: %s %v", out, e)
	}
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		s, err = status()
		if err == nil && !s.TUNPending && (s.TUN || s.TUNError != "") {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !s.TUN {
		t.Fatalf("TUN did not start: %+v %v", s, err)
	}
	t.Log("filtered GUI launched elevated worker and reported TUN active")
	query := new(dns.Msg)
	query.SetQuestion("netflow-test.example.", dns.TypeA)
	answer, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(query, "8.8.8.8:53")
	if err != nil || len(answer.Answer) == 0 {
		t.Fatalf("TUN DNS interception: %v", err)
	}
	record, ok := answer.Answer[0].(*dns.A)
	if !ok || !strings.HasPrefix(record.A.String(), "198.18.") {
		t.Fatalf("unexpected fake IP: %+v", answer.Answer)
	}
	fakeIP := record.A.String()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(fakeIP, "18765"))
	}}
	defer transport.CloseIdleConnections()
	hc := &http.Client{Timeout: 6 * time.Second, Transport: transport}
	if resp, e := hc.Get("http://netflow-test.example:18765/health"); e == nil {
		resp.Body.Close()
		t.Fatal("REJECT rule did not block traffic")
	}
	if out, e := call("mode", "direct"); e != nil {
		t.Fatalf("direct mode: %s %v", out, e)
	}
	resp, err := hc.Get("http://netflow-test.example:18765/health")
	if err != nil {
		t.Fatalf("DIRECT fake-IP forwarding: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "OK" {
		t.Fatalf("unexpected HTTP response: %s %v", body, err)
	}
	t.Log("TUN DNS interception, REJECT and DIRECT fake-IP forwarding verified")
	if out, e := call("tun", "off"); e != nil {
		t.Fatalf("TUN off request: %s %v", out, e)
	}
	restored := false
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s, err = status()
		routes, servers, e := vmNetworkSnapshot()
		if err == nil && e == nil && !s.TUNPending && !s.TUN && reflect.DeepEqual(routes, beforeRoutes) && reflect.DeepEqual(servers, beforeDNS) {
			restored = true
			break
		}
		time.Sleep(time.Second)
	}
	if !restored {
		routes, servers, _ := vmNetworkSnapshot()
		t.Fatalf("TUN shutdown did not restore networking: status=%+v error=%v\nroutes before=%v after=%v\nDNS before=%v after=%v", s, err, beforeRoutes, routes, beforeDNS, servers)
	}
	t.Log("original IPv4/IPv6 routes and adapter DNS restored")
	if out, e := call("tun", "on"); e != nil {
		t.Fatalf("second TUN on: %s %v", out, e)
	}
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		s, err = status()
		if err == nil && !s.TUNPending && (s.TUN || s.TUNError != "") {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !s.TUN {
		t.Fatalf("second TUN failed: %+v %v", s, err)
	}
	if err := gui.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = gui.Wait()
	waitRestored := func(label string) {
		t.Helper()
		end := time.Now().Add(60 * time.Second)
		for time.Now().Before(end) {
			routes, servers, e := vmNetworkSnapshot()
			if e == nil && reflect.DeepEqual(routes, beforeRoutes) && reflect.DeepEqual(servers, beforeDNS) {
				return
			}
			time.Sleep(time.Second)
		}
		routes, servers, _ := vmNetworkSnapshot()
		t.Fatalf("%s did not restore networking: routes before=%v after=%v; DNS before=%v after=%v", label, beforeRoutes, routes, beforeDNS, servers)
	}
	waitRestored("GUI crash")
	t.Log("worker removed TUN and restored routes after GUI termination")

	unsafeDir := t.TempDir()
	provider := filepath.Join(unsafeDir, "provider.yaml")
	if err := os.WriteFile(provider, []byte("proxies:\n  - {name: test, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: test}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKIP_SAFE_PATH_CHECK", "true")
	t.Setenv("SAFE_PATHS", unsafeDir)
	workerContext, stopLaunch := context.WithTimeout(context.Background(), 30*time.Second)
	worker, err := coreipc.LaunchWindows(workerContext, filepath.Join(install, "netflow-kernel-worker.exe"))
	stopLaunch()
	if err != nil {
		t.Fatalf("launch worker: %v", err)
	}
	defer worker.Close()
	workerDir := t.TempDir()
	unsafeConfig := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ntun: {enable: false}\nproxy-providers:\n  external:\n    type: file\n    path: " + strconv.Quote(filepath.ToSlash(provider)) + "\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(workerDir, "config.yaml"), []byte(unsafeConfig), 0600); err != nil {
		t.Fatal(err)
	}
	err = worker.Start(workerDir)
	if err == nil {
		_ = worker.Stop()
		t.Fatal("elevated worker accepted an external provider through unsafe environment variables")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "path is not subpath") {
		t.Fatalf("unexpected external provider error: %v", err)
	}
	t.Log("elevated worker rejected inherited unsafe path exceptions")
	workerConfig := strings.Replace(config, "MATCH,REJECT", "MATCH,DIRECT", 1)
	composed, err := tun.Compose([]byte(workerConfig), true, "NetFlowVM")
	if err != nil {
		t.Fatal(err)
	}
	writeStack := func(stack string) {
		t.Helper()
		data, e := kernelopts.Compose(composed, kernelopts.Options{TUNStack: &stack})
		if e == nil {
			e = os.WriteFile(filepath.Join(workerDir, "config.yaml"), data, 0600)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	writeStack("system")
	if err := worker.Start(workerDir); err != nil {
		t.Fatalf("start worker: %v", err)
	}
	for i, stack := range []string{"system", "mixed", "gvisor", "mips"} {
		if i > 0 {
			writeStack(stack)
			if err := worker.Reload(); err != nil {
				t.Fatalf("%s stack reload: %v", stack, err)
			}
		}
		if !worker.Status().TUN {
			t.Fatalf("%s TUN is not active", stack)
		}
		if _, err := net.InterfaceByName("NetFlowVM"); err != nil {
			t.Fatalf("%s Wintun adapter: %v", stack, err)
		}
		answer, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(query, "8.8.8.8:53")
		if err != nil || len(answer.Answer) == 0 {
			t.Fatalf("%s DNS interception: %v", stack, err)
		}
		record, ok := answer.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("%s invalid fake IP", stack)
		}
		currentIP := record.A.String()
		hc := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(currentIP, "18765"))
		}}}
		response, err := hc.Get("http://netflow-test.example:18765/health")
		if err != nil {
			t.Fatalf("%s fake-IP forwarding: %v", stack, err)
		}
		data, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || string(data) != "OK" {
			t.Fatalf("%s forwarding response: %q %v", stack, data, e)
		}
		t.Logf("%s Windows TUN stack forwarded fake-IP traffic", stack)
	}
	if err := worker.Close(); err != nil {
		t.Fatalf("close worker: %v", err)
	}
	waitRestored("worker disconnect")
	t.Log("worker disconnect restored IPv4/IPv6 routes and DNS")
}
