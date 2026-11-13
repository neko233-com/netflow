//go:build windows && integration

package app

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/neko233-com/netflow"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed testdata/GeoIP2-Country-Test.mmdb
var vmGeoFixture []byte

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
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 15*time.Second)
	versionOutput, versionErr := vmCommand(versionCtx, agentExe, "version").CombinedOutput()
	versionCancel()
	var version struct {
		Version string `json:"version"`
	}
	if versionErr != nil || json.Unmarshal(versionOutput, &version) != nil || version.Version != netflow.Version() {
		t.Fatalf("installed CLI version differs from test manifest: %s %v", versionOutput, versionErr)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	_, _, startupErr := key.GetStringValue("NetFlowVMVerify")
	_ = key.Close()
	if !errors.Is(startupErr, registry.ErrNotExist) {
		t.Fatalf("validation agent left a startup entry: %v", startupErr)
	}
	t.Log("installed CLI version matches and validation agent has no startup entry")
	verge := t.TempDir()
	if err := os.Mkdir(filepath.Join(verge, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(verge, "sets"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"nodes.yaml": "proxies: [{name: migrated-provider-node, type: direct}]\n", "rules.yaml": "payload: ['+.blocked.netflow-test.example']\n"} {
		if err := os.WriteFile(filepath.Join(verge, "sets", name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(verge, "profiles.yaml"), []byte("current: p1\nitems:\n  - {uid: p1, type: remote, name: Test, url: 'https://example.test/sub', file: p1.yaml, option: {proxies: p2, groups: g1, merge: m1}}\n  - {uid: p2, type: proxies, file: p2.yaml}\n  - {uid: g1, type: groups, file: g1.yaml}\n  - {uid: m1, type: merge, file: m1.yaml}\n  - {uid: Merge, type: merge, file: Merge.yaml}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	migrationDNS := reservation.LocalAddr().String()
	_ = reservation.Close()
	vergeConfig := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nipv6: false\nproxies: [{name: old, type: socks5, server: 127.0.0.1, port: 2}]\nproxy-groups: [{name: Select, type: select, proxies: [old, DIRECT]}]\ndns:\n  enable: true\n  listen: '%s'\n  enhanced-mode: redir-host\n  use-hosts: true\n  nameserver: ['127.0.0.1:3']\n  fallback: ['127.0.0.1:2']\nrules: ['RULE-SET,blocked,REJECT', 'MATCH,DIRECT']\n", migrationDNS)
	if err := os.WriteFile(filepath.Join(verge, "profiles", "p1.yaml"), []byte(vergeConfig), 0600); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"p2.yaml":    "prepend: [{name: new, type: socks5, server: 127.0.0.1, port: 2}]\ndelete: [old]\n",
		"g1.yaml":    "append: [{name: Extra, type: select, proxies: [DIRECT]}, {name: FromSet, type: select, use: [imported]}]\n",
		"m1.yaml":    "profile: {store-selected: true}\nproxy-providers:\n  imported: {type: file, path: ./sets/nodes.yaml, health-check: {enable: false}}\nrule-providers:\n  blocked: {type: file, behavior: domain, format: yaml, path: ./sets/rules.yaml}\n",
		"Merge.yaml": "profile: {store-fake-ip: false}\n",
	} {
		if err := os.WriteFile(filepath.Join(verge, "profiles", name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(verge, "verge.yaml"), []byte("profile_dns_settings:\n  p1: {enabled: true}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verge, "dns_config.yaml"), []byte("dns:\n  nameserver: ['127.0.0.1:1']\n  fallback: []\nhosts:\n  imported.netflow-test.example: 192.0.2.77\n"), 0600); err != nil {
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
	func() {
		if err := os.WriteFile(filepath.Join(migrationTarget, "settings.json"), []byte(`{"prefs":"{\"SilentStart\":true}"}`), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		gui := vmCommand(ctx, filepath.Join(install, "NetFlow.exe"))
		gui.Env = append(os.Environ(), "NETFLOW_CONFIG_DIR="+migrationTarget, "GOMAXPROCS=1")
		log, err := os.Create(filepath.Join(migrationTarget, "migration-gui.log"))
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		gui.Stdout, gui.Stderr = log, log
		if err := gui.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = gui.Process.Kill(); _ = gui.Wait() }()
		query := new(dns.Msg)
		query.SetQuestion("imported.netflow-test.example.", dns.TypeA)
		var response *dns.Msg
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			response, _, err = (&dns.Client{Timeout: time.Second}).Exchange(query, migrationDNS)
			if err == nil && response != nil && len(response.Answer) > 0 {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || response == nil || len(response.Answer) == 0 {
			data, _ := os.ReadFile(filepath.Join(migrationTarget, "migration-gui.log"))
			t.Fatalf("migrated DNS did not start: %v %s", err, data)
		}
		answer, ok := response.Answer[0].(*dns.A)
		if !ok || answer.A.String() != "192.0.2.77" {
			t.Fatalf("migrated hosts not applied: %v", response.Answer)
		}
		commandCtx, commandCancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err := vmCommand(commandCtx, agentExe, "--config-dir", migrationTarget, "groups").CombinedOutput()
		commandCancel()
		if err != nil {
			t.Fatalf("migrated groups query failed: %s: %v", out, err)
		}
		var groups agent.GroupsResult
		if err := json.Unmarshal(out, &groups); err != nil {
			t.Fatalf("invalid groups response: %s: %v", out, err)
		}
		selectFound, extraFound, newFound := false, false, false
		for _, group := range groups.Groups {
			if group.Name == "Extra" {
				extraFound = true
			}
			if group.Name == "Select" {
				selectFound = true
				for _, node := range group.Nodes {
					if node.Name == "old" {
						t.Fatal("deleted proxy remained in migrated group")
					}
					if node.Name == "new" {
						newFound = true
					}
				}
			}
		}
		if !selectFound || !extraFound || !newFound {
			t.Fatalf("migrated proxy extensions missing: %s", out)
		}
		// The provider belongs to a group added by the imported extension. Its
		// contents must survive the switch to the privileged TUN worker.
		callMigration := func(args ...string) ([]byte, error) {
			c, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			return vmCommand(c, agentExe, append([]string{"--config-dir", migrationTarget}, args...)...).CombinedOutput()
		}
		if out, err := callMigration("tun", "on"); err != nil {
			t.Fatalf("migrated TUN on: %s %v", out, err)
		}
		var status agent.Status
		deadline = time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			out, err = callMigration("status")
			if err == nil {
				err = json.Unmarshal(out, &status)
			}
			if err == nil && !status.TUNPending && (status.TUN || status.TUNError != "") {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || !status.TUN {
			t.Fatalf("migrated TUN failed: %+v %v", status, err)
		}
		out, err = callMigration("groups")
		if err != nil || !strings.Contains(string(out), "migrated-provider-node") {
			t.Fatalf("migrated provider unavailable in TUN: %s %v", out, err)
		}
		out, err = callMigration("rules")
		if err != nil || !strings.Contains(string(out), "blocked") {
			t.Fatalf("migrated rule provider unavailable in TUN: %s %v", out, err)
		}
		if out, err := callMigration("tun", "off"); err != nil {
			t.Fatalf("migrated TUN off: %s %v", out, err)
		}
		deadline = time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			out, err = callMigration("status")
			if err == nil {
				err = json.Unmarshal(out, &status)
			}
			if err == nil && !status.TUNPending && !status.TUN {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || status.TUNPending || status.TUN {
			t.Fatalf("migrated TUN did not stop: %+v %v", status, err)
		}
	}()
	t.Log("migrated DNS, hosts, proxy and group extensions applied by installed GUI")
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
	dnsListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := dnsListener.LocalAddr().String()
	dnsListener.Close()
	dir := t.TempDir()
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\nmode: rule\nprofile: {store-fake-ip: true}\ndns:\n  enable: true\n  listen: '%s'\n  enhanced-mode: fake-ip\n  nameserver: ['%s']\ntun:\n  enable: false\n  stack: system\n  auto-route: true\n  auto-detect-interface: true\nrules:\n  - MATCH,REJECT\n", dnsAddress, packet.LocalAddr().String())
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
	defer func() {
		if !t.Failed() {
			return
		}
		_ = logFile.Sync()
		data, _ := os.ReadFile(filepath.Join(dir, "gui.log"))
		if len(data) > 65536 {
			data = data[len(data)-65536:]
		}
		t.Logf("GUI log tail: %s", data)
		if handle, openErr := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(gui.Process.Pid)); openErr == nil {
			var code uint32
			exitErr := windows.GetExitCodeProcess(handle, &code)
			_ = windows.CloseHandle(handle)
			t.Logf("GUI process exit code: %d (0x%08X), query error: %v", code, code, exitErr)
		} else {
			t.Logf("GUI process query failed: %v", openErr)
		}
		entries, readErr := os.ReadDir(filepath.Join(dir, "agent"))
		t.Logf("Agent endpoint files: %d, read error: %v", len(entries), readErr)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "endpoint-") || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			var endpoint struct {
				Address string `json:"address"`
			}
			content, fileErr := os.ReadFile(filepath.Join(dir, "agent", entry.Name()))
			if fileErr != nil || json.Unmarshal(content, &endpoint) != nil {
				continue
			}
			host, _, splitErr := net.SplitHostPort(endpoint.Address)
			if splitErr != nil || host != "127.0.0.1" {
				continue
			}
			connection, dialErr := net.DialTimeout("tcp", endpoint.Address, 3*time.Second)
			if connection != nil {
				_ = connection.Close()
			}
			t.Logf("Agent loopback endpoint reachable: %v", dialErr == nil)
		}
	}()
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
	diagnosticOutput, diagnosticErr := call("diagnostics")
	var diagnostics agent.Diagnostics
	if diagnosticErr != nil || json.Unmarshal(diagnosticOutput, &diagnostics) != nil || diagnostics.AppVersion != netflow.Version() || diagnostics.CoreVersion != core.Version() || diagnostics.CoreVersion == "unknown" || !diagnostics.CoreRunning || diagnostics.TUN {
		t.Fatalf("installed CLI diagnostics mismatch: %s %v", diagnosticOutput, diagnosticErr)
	}
	t.Log("installed CLI diagnostics match application and kernel build versions")
	lookupFake := func(name, server string) string {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		answer, _, e := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(query, server)
		if e != nil || len(answer.Answer) == 0 {
			t.Fatalf("fake-IP lookup for %s: %v", name, e)
		}
		record, ok := answer.Answer[0].(*dns.A)
		if !ok || !strings.HasPrefix(record.A.String(), "198.18.") {
			t.Fatalf("unexpected fake IP for %s: %+v", name, answer.Answer)
		}
		return record.A.String()
	}
	alpha := lookupFake("alpha.netflow-test.example.", dnsAddress)
	beta := lookupFake("beta.netflow-test.example.", dnsAddress)
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
	if lookupFake("beta.netflow-test.example.", dnsAddress) != beta || lookupFake("alpha.netflow-test.example.", dnsAddress) != alpha {
		t.Fatal("Fake-IP mappings changed when switching to the privileged worker")
	}
	t.Log("persistent Fake-IP mappings survived the switch to the privileged worker")
	query := new(dns.Msg)
	query.SetQuestion("netflow-test.example.", dns.TypeA)
	var answer *dns.Msg
	var firstErr error
	readyAt := time.Now()
	deadline = readyAt.Add(30 * time.Second)
	for time.Now().Before(deadline) {
		answer, _, err = (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).Exchange(query, "8.8.8.8:53")
		if err == nil && answer != nil && len(answer.Answer) > 0 {
			break
		}
		if firstErr == nil {
			firstErr = err
		}
		time.Sleep(time.Second)
	}
	if err != nil || answer == nil || len(answer.Answer) == 0 {
		routes, servers, networkErr := vmNetworkSnapshot()
		data, _ := os.ReadFile(filepath.Join(dir, "gui.log"))
		t.Fatalf("TUN DNS interception: %v (first %v, network %v, routes %v, DNS %v, GUI %s)", err, firstErr, networkErr, routes, servers, data)
	}
	if firstErr != nil {
		t.Logf("TUN DNS became ready after %s; first request: %v", time.Since(readyAt).Round(time.Millisecond), firstErr)
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
	if lookupFake("netflow-test.example.", dnsAddress) != fakeIP || lookupFake("alpha.netflow-test.example.", dnsAddress) != alpha || lookupFake("beta.netflow-test.example.", dnsAddress) != beta {
		t.Fatal("Fake-IP mappings changed when returning to the desktop kernel")
	}
	t.Log("persistent Fake-IP mappings survived the switch back to the desktop kernel")
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
	stageDir, err := worker.StageDirectory()
	if err != nil {
		t.Fatalf("isolated worker directory: %v", err)
	}
	if _, err := os.ReadDir(stageDir); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("filtered user could access privileged directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "unauthorized.txt"), []byte("x"), 0600); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("filtered user could modify privileged directory: %v", err)
	}
	t.Log("filtered user cannot read or modify the privileged kernel directory")
	// A provider path under the source directory can be a junction to another
	// directory. The elevated worker must materialize it inside its own stage.
	junction := filepath.Join(workerDir, "junction")
	junctionContext, junctionCancel := context.WithTimeout(context.Background(), 15*time.Second)
	junctionOutput, junctionErr := vmCommand(junctionContext, "cmd.exe", "/c", "mklink", "/J", junction, unsafeDir).CombinedOutput()
	junctionCancel()
	if junctionErr != nil {
		t.Fatalf("create test junction: %s %v", junctionOutput, junctionErr)
	}
	originalProvider, err := os.ReadFile(provider)
	if err != nil {
		t.Fatal(err)
	}
	junctionConfig := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ntun: {enable: false}\nproxy-providers:\n  linked:\n    type: http\n    url: 'http://10.233.42.1:18765/v1/provider.yaml'\n    path: junction/provider.yaml\n    interval: 3600\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(workerDir, "config.yaml"), []byte(junctionConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(workerDir); err != nil {
		t.Fatalf("start junction provider: %v", err)
	}
	if err := worker.UpdateProxyProvider("linked"); err != nil {
		t.Fatalf("update junction provider: %v", err)
	}
	if err := worker.Stop(); err != nil {
		t.Fatalf("stop junction provider: %v", err)
	}
	afterProvider, err := os.ReadFile(provider)
	if err != nil || string(afterProvider) != string(originalProvider) {
		t.Fatalf("provider update followed unprivileged junction: %v", err)
	}
	t.Log("provider update did not follow a junction in the user's directory")
	if err := os.Mkdir(filepath.Join(workerDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workerDir, "Country.mmdb"), vmGeoFixture, 0600); err != nil {
		t.Fatal(err)
	}
	localProvider := filepath.Join(workerDir, "providers", "nodes.yaml")
	providerBody := "proxies:\n  - {name: test, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: test}\n"
	if err := os.WriteFile(localProvider, []byte(providerBody), 0600); err != nil {
		t.Fatal(err)
	}
	workerConfig := strings.Replace(config, "MATCH,REJECT", "MATCH,DIRECT", 1)
	workerConfig = strings.Replace(workerConfig, "  - MATCH,DIRECT", "  - GEOIP,US,DIRECT\n  - MATCH,DIRECT", 1)
	workerConfig += "\nproxy-providers:\n  local:\n    type: file\n    path: providers/nodes.yaml\n"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controllerAddress := listener.Addr().String()
	listener.Close()
	workerConfig += "external-controller: " + strconv.Quote(controllerAddress) + "\nsecret: test-controller-secret\n"
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
	if conn, err := net.DialTimeout("tcp4", controllerAddress, time.Second); err == nil {
		conn.Close()
		t.Fatal("privileged kernel exposed an external controller")
	}
	t.Log("privileged kernel did not expose the configured external controller")
	checkProvider := func(count int) {
		t.Helper()
		for _, p := range worker.ProxyProviders() {
			if p.Name == "local" && p.Count == count {
				return
			}
		}
		t.Fatalf("isolated provider does not contain %d nodes: %+v", count, worker.ProxyProviders())
	}
	checkProvider(1)
	providerBody += "  - {name: second, type: ss, server: 127.0.0.1, port: 2, cipher: aes-128-gcm, password: test}\n"
	if err := os.WriteFile(localProvider, []byte(providerBody), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.Reload(); err != nil {
		t.Fatalf("reload isolated provider: %v", err)
	}
	checkProvider(2)
	t.Log("unprivileged provider files were copied and refreshed inside the isolated worker")
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

	launchWorker := func() *coreipc.Client {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, err := coreipc.LaunchWindows(ctx, filepath.Join(install, "netflow-kernel-worker.exe"))
		if err != nil {
			t.Fatalf("launch test worker: %v", err)
		}
		return client
	}
	containsPath := func(paths []string, want string) bool {
		for _, path := range paths {
			if strings.EqualFold(filepath.Clean(path), filepath.Clean(want)) {
				return true
			}
		}
		return false
	}
	victim := launchWorker()
	defer victim.Close()
	if err := victim.Start(workerDir); err != nil {
		t.Fatalf("start worker for forced termination: %v", err)
	}
	victimStage, err := victim.StageDirectory()
	if err != nil {
		t.Fatal(err)
	}
	observerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(observerDir, "config.yaml"), []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	observer := launchWorker()
	if err := observer.Start(observerDir); err != nil {
		observer.Close()
		t.Fatalf("start active-stage observer: %v", err)
	}
	cleaned, err := observer.CleanedStages()
	if err != nil || containsPath(cleaned, victimStage) {
		observer.Close()
		t.Fatalf("active worker stage was considered abandoned: %v %v", cleaned, err)
	}
	if err := observer.Close(); err != nil {
		t.Fatalf("close observer: %v", err)
	}
	if err := coreipc.TerminateWorkerForIntegration(victim); err != nil {
		t.Fatalf("terminate isolated worker: %v", err)
	}
	if err := victim.Close(); err == nil {
		t.Fatal("forced worker termination was not reported")
	}
	waitRestored("forced worker termination")
	cleaner := launchWorker()
	defer cleaner.Close()
	if err := cleaner.Start(observerDir); err != nil {
		t.Fatalf("start abandoned-stage cleaner: %v", err)
	}
	cleaned, err = cleaner.CleanedStages()
	if err != nil || !containsPath(cleaned, victimStage) {
		t.Fatalf("abandoned worker stage was not cleaned: %v %v", cleaned, err)
	}
	if err := cleaner.Close(); err != nil {
		t.Fatalf("close cleaner: %v", err)
	}
	t.Log("forced worker termination restored networking; the next worker cleaned its abandoned private stage without touching an active stage")

	// Repeat only the handoff with the default in-memory cache; the full TUN
	// stack and crash tests above use persistent fake-IP storage.
	memoryDir := t.TempDir()
	memoryConfig := strings.Replace(config, "store-fake-ip: true", "store-fake-ip: false", 1)
	if err := os.WriteFile(filepath.Join(memoryDir, "config.yaml"), []byte(memoryConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(memoryDir, "settings.json"), []byte(`{"prefs":"{\"SilentStart\":true}"}`), 0600); err != nil {
		t.Fatal(err)
	}
	memoryContext, stopMemory := context.WithCancel(context.Background())
	defer stopMemory()
	memoryGUI := vmCommand(memoryContext, filepath.Join(install, "NetFlow.exe"))
	memoryGUI.Env = append(os.Environ(), "NETFLOW_CONFIG_DIR="+memoryDir, "GOMAXPROCS=1")
	memoryLog, err := os.Create(filepath.Join(memoryDir, "gui.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer memoryLog.Close()
	memoryGUI.Stdout, memoryGUI.Stderr = memoryLog, memoryLog
	if err := memoryGUI.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = memoryGUI.Process.Kill(); _ = memoryGUI.Wait() }()
	memoryCall := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return vmCommand(ctx, agentExe, append([]string{"--config-dir", memoryDir}, args...)...).CombinedOutput()
	}
	memoryStatus := func() (agent.Status, error) {
		var result agent.Status
		out, err := memoryCall("status")
		if err == nil {
			err = json.Unmarshal(out, &result)
		}
		return result, err
	}
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s, err = memoryStatus()
		if err == nil && s.Running {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !s.Running {
		data, _ := os.ReadFile(filepath.Join(memoryDir, "gui.log"))
		t.Fatalf("memory-cache GUI startup: %+v %v %s", s, err, data)
	}
	memoryA := lookupFake("memory-a.netflow-test.example.", dnsAddress)
	memoryB := lookupFake("memory-b.netflow-test.example.", dnsAddress)
	for _, enabled := range []bool{true, false} {
		action := "off"
		if enabled {
			action = "on"
		}
		if out, e := memoryCall("tun", action); e != nil {
			data, _ := os.ReadFile(filepath.Join(memoryDir, "gui.log"))
			eventCtx, eventCancel := context.WithTimeout(context.Background(), 10*time.Second)
			events, eventErr := vmCommand(eventCtx, "wevtutil.exe", "qe", "Application", "/q:*[System[(EventID=1000 or EventID=1001)]]", "/c:5", "/rd:true", "/f:text").CombinedOutput()
			eventCancel()
			t.Fatalf("memory-cache TUN %s: %s %v\nGUI log: %s\nApplication events (%v): %s", action, out, e, data, eventErr, events)
		}
		deadline = time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			s, err = memoryStatus()
			if err == nil && !s.TUNPending && (s.TUN == enabled || s.TUNError != "") {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || s.TUN != enabled || s.TUNError != "" {
			t.Fatalf("memory-cache TUN %s: %+v %v", action, s, err)
		}
		if lookupFake("memory-b.netflow-test.example.", dnsAddress) != memoryB || lookupFake("memory-a.netflow-test.example.", dnsAddress) != memoryA {
			t.Fatalf("in-memory Fake-IP changed after TUN %s", action)
		}
	}
	waitRestored("memory-cache TUN shutdown")
	t.Log("in-memory Fake-IP mappings survived both TUN switches")
}
