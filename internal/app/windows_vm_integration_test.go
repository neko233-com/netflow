//go:build windows && integration

package app

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/neko233-com/netflow"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/geoupdate"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/validation"
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

func vmVisibleWindows(pid uint32) int {
	user32 := windows.NewLazySystemDLL("user32.dll")
	enum := user32.NewProc("EnumWindows")
	windowPID := user32.NewProc("GetWindowThreadProcessId")
	visible := user32.NewProc("IsWindowVisible")
	count := 0
	callback := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var owner uint32
		windowPID.Call(hwnd, uintptr(unsafe.Pointer(&owner)))
		if owner == pid {
			if shown, _, _ := visible.Call(hwnd); shown != 0 {
				count++
			}
		}
		return 1
	})
	if result, _, _ := enum.Call(callback, 0); result == 0 {
		return -1
	}
	return count
}

func vmAgentJunctionSafety(t *testing.T) {
	t.Helper()
	base := t.TempDir()
	config, outside := filepath.Join(base, "config"), filepath.Join(base, "outside")
	if err := os.Mkdir(config, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(config, "agent")
	c, done := context.WithTimeout(context.Background(), 15*time.Second)
	out, err := vmCommand(c, "cmd.exe", "/c", "mklink", "/J", link, outside).CombinedOutput()
	done()
	if err != nil {
		t.Fatalf("create Agent junction: %s %v", out, err)
	}
	defer os.Remove(link)
	if bridge, err := agent.Start(config, func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }); err == nil {
		_ = bridge.Close()
		t.Fatal("Agent started through a junction")
	}
	if err := (agent.Client{Dir: config}).Call(context.Background(), "status", nil, nil); err == nil {
		t.Fatal("Agent discovery followed a junction")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("Agent created files outside configuration directory")
	}
}

func vmHeadlessRoundTrip(t *testing.T, agentExe, dir string) {
	t.Helper()
	beforeRoutes, beforeDNS, err := vmNetworkSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "headless-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	webdavReceived := make(chan [32]byte, 1)
	var webdavMu sync.Mutex
	var webdavBody []byte
	var webdavName string
	webdavServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "vm-user" || password != "synthetic-webdav-secret" || r.URL.RawQuery != "token=synthetic-webdav-token" {
			http.Error(w, "invalid request", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "precondition missing", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
			if err != nil {
				http.Error(w, "read failed", http.StatusBadRequest)
				return
			}
			webdavMu.Lock()
			webdavBody, webdavName = body, filepath.Base(r.URL.Path)
			webdavMu.Unlock()
			webdavReceived <- sha256.Sum256(body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			webdavMu.Lock()
			defer webdavMu.Unlock()
			if webdavName == "" || filepath.Base(r.URL.Path) != webdavName {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(webdavBody)
		case "PROPFIND":
			if r.Header.Get("Depth") != "1" {
				http.Error(w, "invalid depth", http.StatusBadRequest)
				return
			}
			webdavMu.Lock()
			defer webdavMu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/collection/%s</d:href><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, webdavName)
		default:
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		}
	}))
	defer webdavServer.Close()
	certPath := filepath.Join(t.TempDir(), "webdav-test-ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: webdavServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := vmCommand(ctx, agentExe, "--config-dir", dir, "serve")
	for _, entry := range os.Environ() {
		upper := strings.ToUpper(entry)
		if !strings.HasPrefix(upper, "SSL_CERT_FILE=") && !strings.HasPrefix(upper, "GODEBUG=") {
			server.Env = append(server.Env, entry)
		}
	}
	server.Env = append(server.Env, "SSL_CERT_FILE="+certPath, "GODEBUG="+os.Getenv("GODEBUG")+",x509sslcertoverrideplatform=1")
	server.Stdout, server.Stderr = logFile, logFile
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = server.Process.Kill()
			<-finished
		}
		if t.Failed() {
			_ = logFile.Sync()
			data, _ := os.ReadFile(logFile.Name())
			if len(data) > 65536 {
				data = data[len(data)-65536:]
			}
			t.Logf("headless log tail: %s", data)
		}
	}()
	call := func(args ...string) ([]byte, error) {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		return vmCommand(c, agentExe, append([]string{"--config-dir", dir}, args...)...).CombinedOutput()
	}
	var status agent.Status
	deadline := time.Now().Add(100 * time.Second)
	for time.Now().Before(deadline) {
		out, callErr := call("status")
		if callErr == nil && json.Unmarshal(out, &status) == nil && !status.TUNPending && status.TUN {
			break
		}
		time.Sleep(time.Second)
	}
	if !status.TUN || !status.Headless {
		t.Fatalf("headless TUN did not start: %+v", status)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "agent"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("headless endpoint unavailable: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "agent", entries[0].Name()))
	endpointFile, openErr := os.Open(filepath.Join(dir, "agent", entries[0].Name()))
	if openErr != nil {
		t.Fatal(openErr)
	}
	sd, aclErr := windows.GetSecurityInfo(windows.Handle(endpointFile.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	_ = endpointFile.Close()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if aclErr != nil || userErr != nil || !strings.Contains(sd.String(), "D:P") || !strings.Contains(sd.String(), user.User.Sid.String()) || strings.Count(sd.String(), "(A;") != 2 {
		t.Fatal("headless Agent endpoint lacks its protected user-only ACL")
	}
	var endpoint struct {
		PID uint32 `json:"pid"`
	}
	if err != nil || json.Unmarshal(data, &endpoint) != nil || endpoint.PID == 0 {
		t.Fatal("invalid headless endpoint")
	}
	if windows := vmVisibleWindows(endpoint.PID); windows != 0 {
		t.Fatalf("headless process has %d visible windows", windows)
	}
	var downloads atomic.Int32
	subscription := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscription" && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		downloads.Add(1)
		_, _ = io.WriteString(w, "mixed-port: 0\nport: 0\nsocks-port: 0\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n")
	}))
	defer subscription.Close()
	waitJob := func(job agent.ProfileJob) agent.ProfileJob {
		t.Helper()
		until := time.Now().Add(30 * time.Second)
		for job.State == "pending" && time.Now().Before(until) {
			payload, e := call("profile-job-status", job.JobID)
			if e != nil || json.Unmarshal(payload, &job) != nil {
				t.Fatalf("headless profile job query failed: %s %v", payload, e)
			}
			if job.State == "pending" {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return job
	}
	importProfile := func(path string) agent.ProfileJob {
		t.Helper()
		body, _ := json.Marshal(agent.ProfileImportArgs{URL: subscription.URL + path + "?token=synthetic-secret", Name: "headless-test"})
		c, done := context.WithTimeout(context.Background(), 30*time.Second)
		command := vmCommand(c, agentExe, "--config-dir", dir, "import-profile")
		command.Stdin = strings.NewReader(string(body))
		payload, e := command.CombinedOutput()
		done()
		var job agent.ProfileJob
		if e != nil || strings.Contains(string(payload), "synthetic-secret") || json.Unmarshal(payload, &job) != nil {
			t.Fatalf("headless profile import request failed: %s %v", payload, e)
		}
		return waitJob(job)
	}
	profileJob := importProfile("/subscription")
	if profileJob.State != "succeeded" || profileJob.ProfileID == "" {
		t.Fatalf("headless profile import: %+v", profileJob)
	}
	payload, err := call("update-profile", profileJob.ProfileID)
	var updateJob agent.ProfileJob
	if err != nil || json.Unmarshal(payload, &updateJob) != nil {
		t.Fatalf("headless profile update request failed: %s %v", payload, err)
	}
	if updateJob = waitJob(updateJob); updateJob.State != "succeeded" || downloads.Load() < 2 {
		t.Fatalf("headless profile update: %+v", updateJob)
	}
	if payload, err := call("delete-profile", profileJob.ProfileID); err != nil {
		t.Fatalf("headless profile delete failed: %s %v", payload, err)
	}
	// A URL with userinfo and a query but no path previously leaked its
	// credentials when the default profile name was derived from raw text.
	address := strings.Replace(subscription.URL, "http://", "http://synthetic-user:synthetic-password@", 1) + "?token=synthetic-secret"
	defaultArgs, _ := json.Marshal(agent.ProfileImportArgs{URL: address})
	requestCtx, requestDone := context.WithTimeout(context.Background(), 30*time.Second)
	request := vmCommand(requestCtx, agentExe, "--config-dir", dir, "import-profile")
	request.Stdin = strings.NewReader(string(defaultArgs))
	payload, err = request.CombinedOutput()
	requestDone()
	var defaultJob agent.ProfileJob
	if err != nil || json.Unmarshal(payload, &defaultJob) != nil || strings.Contains(string(payload), "synthetic-") {
		t.Fatalf("default-name import failed or leaked: %v", err)
	}
	defaultJob = waitJob(defaultJob)
	if defaultJob.State != "succeeded" || defaultJob.ProfileID == "" {
		t.Fatalf("default-name import failed: %+v", defaultJob)
	}
	payload, err = call("profiles")
	if err != nil || strings.Contains(string(payload), "synthetic-") {
		t.Fatal("Agent exposed URL credentials in a default profile name")
	}
	profileStore := profile.NewStore(dir)
	sharedCatalog, err := profileStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	var sharedItem profile.CatalogItem
	for _, item := range sharedCatalog.Items {
		if item.UID == defaultJob.ProfileID {
			sharedItem = item
			break
		}
	}
	if sharedItem.UID == "" {
		t.Fatal("imported profile missing")
	}
	sharedItem.UID, sharedItem.Name = "shared-test-fixture", "shared-test-fixture"
	sharedCatalog.Items = append(sharedCatalog.Items, sharedItem)
	if err := profileStore.Save(sharedCatalog); err != nil {
		t.Fatal(err)
	}
	if payload, err := call("delete-profile", defaultJob.ProfileID); err != nil {
		t.Fatalf("shared profile delete failed: %s %v", payload, err)
	}
	sharedPath := filepath.Join(dir, sharedItem.File)
	if _, err := os.Stat(sharedPath); err != nil {
		t.Fatal("deleting a shared profile removed another entry's file")
	}
	sharedUTF16, err := windows.UTF16PtrFromString(sharedPath)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := windows.CreateFile(sharedUTF16, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, deleteErr := call("delete-profile", sharedItem.UID)
	_ = windows.CloseHandle(locked)
	if deleteErr == nil {
		t.Fatal("delete unexpectedly succeeded while file removal was blocked")
	}
	sharedCatalog, err = profileStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	foundShared := false
	for _, item := range sharedCatalog.Items {
		if item.UID == sharedItem.UID {
			foundShared = true
		}
	}
	if !foundShared {
		t.Fatal("failed deletion did not restore the catalog entry")
	}
	if payload, err := call("delete-profile", sharedItem.UID); err != nil {
		t.Fatalf("retrying profile delete failed: %s %v", payload, err)
	}
	t.Log("installed Agent preserved shared profile data and restored catalog after a blocked file deletion")
	failedJob := importProfile("/missing")
	encodedJob, _ := json.Marshal(failedJob)
	if failedJob.State != "failed" || strings.Contains(string(encodedJob), "synthetic-secret") || strings.Contains(string(encodedJob), subscription.URL) {
		t.Fatal("failed profile job exposed sensitive URL or did not fail")
	}
	t.Log("installed headless Agent imported, updated and deleted an inactive subscription without exposing its URL")
	backupRoot := t.TempDir()
	scheduledDir := filepath.Join(backupRoot, "scheduled")
	if err := os.Mkdir(scheduledDir, 0700); err != nil {
		t.Fatal(err)
	}
	scheduledStart := time.Now()
	payload, err = call("backup-schedule-set", "on", scheduledDir, "1")
	var schedule agent.BackupSchedule
	if err != nil || json.Unmarshal(payload, &schedule) != nil || !schedule.Enabled {
		t.Fatalf("enable schedule: %s %v", payload, err)
	}
	// Advance the due time without waiting an hour; the actual installed
	// scheduler still executes its normal timer in the guest.
	schedule.NextRun = time.Now().UTC().Add(-time.Minute)
	encodedSchedule, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	if err := safepath.WriteFile(dir, scheduleFile, encodedSchedule); err != nil {
		t.Fatal(err)
	}
	scheduledDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(scheduledDeadline) {
		payload, err = call("backup-schedule")
		if err == nil && json.Unmarshal(payload, &schedule) == nil && schedule.NextRun.After(time.Now()) {
			break
		}
		time.Sleep(time.Second)
	}
	archives, err := os.ReadDir(scheduledDir)
	if err != nil || len(archives) != 1 || !schedule.NextRun.After(time.Now()) {
		t.Fatalf("scheduled backup failed: %s %v", payload, err)
	}
	if payload, err := call("backup-schedule-set", "off"); err != nil {
		t.Fatalf("disable schedule: %s %v", payload, err)
	}
	t.Logf("installed headless Agent scheduled a live TUN backup and disabled its schedule in %s", time.Since(scheduledStart).Round(time.Millisecond))
	liveArchive := filepath.Join(backupRoot, "live.zip")
	payload, err = call("backup-create", liveArchive)
	var backupJob agent.BackupJob
	if err != nil || json.Unmarshal(payload, &backupJob) != nil || strings.Contains(string(payload), liveArchive) {
		t.Fatalf("live backup request failed: %s %v", payload, err)
	}
	until := time.Now().Add(45 * time.Second)
	for backupJob.State == "pending" && time.Now().Before(until) {
		payload, err = call("backup-job-status", backupJob.JobID)
		if err != nil || json.Unmarshal(payload, &backupJob) != nil {
			t.Fatalf("live backup job query failed: %s %v", payload, err)
		}
		if backupJob.State == "pending" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if backupJob.State != "succeeded" {
		t.Fatalf("live backup did not complete: %+v", backupJob)
	}
	configArgs, _ := json.Marshal(agent.WebDAVConfigArgs{URL: webdavServer.URL + "/collection/?token=synthetic-webdav-token", User: "vm-user", Password: "synthetic-webdav-secret"})
	requestCtx, requestDone = context.WithTimeout(context.Background(), 30*time.Second)
	request = vmCommand(requestCtx, agentExe, "--config-dir", dir, "webdav-save")
	request.Stdin = strings.NewReader(string(configArgs))
	payload, err = request.CombinedOutput()
	requestDone()
	if err != nil || strings.Contains(string(payload), "synthetic-webdav") {
		t.Fatalf("WebDAV protected save failed or leaked credentials: %v", err)
	}
	payload, err = call("webdav-config")
	var configStatus agent.WebDAVConfigStatus
	if err != nil || json.Unmarshal(payload, &configStatus) != nil || !configStatus.Saved || !configStatus.ProtectedStorageAvailable {
		t.Fatal("WebDAV protected status incorrect")
	}
	settingsData, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil || strings.Contains(string(settingsData), "synthetic-webdav") || strings.Contains(string(settingsData), "vm-user") {
		t.Fatal("WebDAV credentials were stored as plaintext")
	}
	webdavArgs, _ := json.Marshal(agent.WebDAVUploadArgs{Archive: liveArchive, UseSaved: true})
	requestCtx, requestDone = context.WithTimeout(context.Background(), 30*time.Second)
	request = vmCommand(requestCtx, agentExe, "--config-dir", dir, "webdav-upload")
	request.Stdin = strings.NewReader(string(webdavArgs))
	payload, err = request.CombinedOutput()
	requestDone()
	var uploadJob agent.BackupJob
	if err != nil || json.Unmarshal(payload, &uploadJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
		t.Fatalf("WebDAV request rejected or leaked credentials: %v", err)
	}
	until = time.Now().Add(45 * time.Second)
	for uploadJob.State == "pending" && time.Now().Before(until) {
		payload, err = call("backup-job-status", uploadJob.JobID)
		if err != nil || json.Unmarshal(payload, &uploadJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
			t.Fatalf("WebDAV status failed or leaked credentials: %v", err)
		}
		if uploadJob.State == "pending" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if uploadJob.State != "succeeded" || uploadJob.RemoteName == "" {
		t.Fatalf("WebDAV job failed: %+v", uploadJob)
	}
	select {
	case got := <-webdavReceived:
		want, err := vmHash(liveArchive)
		if err != nil || hex.EncodeToString(got[:]) != want {
			t.Fatal("WebDAV upload content mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WebDAV server did not receive backup")
	}
	t.Log("installed headless Agent uploaded a validated backup to a local TLS WebDAV server without leaking credentials")
	listArgs, _ := json.Marshal(agent.WebDAVListArgs{UseSaved: true})
	requestCtx, requestDone = context.WithTimeout(context.Background(), 30*time.Second)
	request = vmCommand(requestCtx, agentExe, "--config-dir", dir, "webdav-list")
	request.Stdin = strings.NewReader(string(listArgs))
	payload, err = request.CombinedOutput()
	requestDone()
	var listJob agent.BackupJob
	if err != nil || json.Unmarshal(payload, &listJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
		t.Fatalf("WebDAV listing request failed or leaked credentials: %v", err)
	}
	until = time.Now().Add(45 * time.Second)
	for listJob.State == "pending" && time.Now().Before(until) {
		payload, err = call("backup-job-status", listJob.JobID)
		if err != nil || json.Unmarshal(payload, &listJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
			t.Fatalf("WebDAV listing status failed or leaked credentials: %v", err)
		}
		if listJob.State == "pending" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if listJob.State != "succeeded" || len(listJob.RemoteNames) != 1 || listJob.RemoteNames[0] != uploadJob.RemoteName {
		t.Fatalf("WebDAV listing failed: %+v", listJob)
	}
	t.Log("installed headless Agent listed the uploaded backup without exposing credentials")
	remoteParent := t.TempDir()
	remoteDestination := filepath.Join(remoteParent, "restored")
	remoteArgs, _ := json.Marshal(agent.WebDAVRestoreArgs{RemoteName: uploadJob.RemoteName, Destination: remoteDestination, UseSaved: true})
	requestCtx, requestDone = context.WithTimeout(context.Background(), 30*time.Second)
	request = vmCommand(requestCtx, agentExe, "--config-dir", dir, "webdav-restore")
	request.Stdin = strings.NewReader(string(remoteArgs))
	payload, err = request.CombinedOutput()
	requestDone()
	var remoteJob agent.BackupJob
	if err != nil || json.Unmarshal(payload, &remoteJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
		t.Fatalf("WebDAV restore request failed or leaked credentials: %v", err)
	}
	until = time.Now().Add(45 * time.Second)
	for remoteJob.State == "pending" && time.Now().Before(until) {
		payload, err = call("backup-job-status", remoteJob.JobID)
		if err != nil || json.Unmarshal(payload, &remoteJob) != nil || strings.Contains(string(payload), "synthetic-webdav") {
			t.Fatalf("WebDAV restore status failed or leaked credentials: %v", err)
		}
		if remoteJob.State == "pending" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	remoteFiles, err := os.ReadDir(remoteParent)
	if err != nil || remoteJob.State != "succeeded" || len(remoteFiles) != 1 {
		t.Fatalf("WebDAV restore failed or left temporary file: %+v %v", remoteJob, err)
	}
	remoteCatalog, e1 := vmHash(filepath.Join(remoteDestination, "profiles.json"))
	currentCatalog, e2 := vmHash(filepath.Join(dir, "profiles.json"))
	if e1 != nil || e2 != nil || remoteCatalog != currentCatalog {
		t.Fatal("WebDAV restore lost profile catalog")
	}
	t.Log("installed headless Agent restored the remote backup into a new directory and removed its temporary download")
	if payload, err := call("webdav-clear"); err != nil || strings.Contains(string(payload), "synthetic-webdav") {
		t.Fatalf("WebDAV protected clear failed: %v", err)
	}
	payload, err = call("webdav-config")
	if err != nil || json.Unmarshal(payload, &configStatus) != nil || configStatus.Saved {
		t.Fatal("WebDAV protected configuration was not cleared")
	}
	t.Log("installed headless Agent protected, used and cleared saved WebDAV credentials")
	restored := filepath.Join(backupRoot, "restored")
	payload, err = call("restore-create", liveArchive, restored)
	var restoreJob agent.BackupJob
	if err != nil || json.Unmarshal(payload, &restoreJob) != nil {
		t.Fatalf("live restore request failed: %s %v", payload, err)
	}
	until = time.Now().Add(45 * time.Second)
	for restoreJob.State == "pending" && time.Now().Before(until) {
		payload, err = call("backup-job-status", restoreJob.JobID)
		if err != nil || json.Unmarshal(payload, &restoreJob) != nil {
			t.Fatalf("live restore job query failed: %s %v", payload, err)
		}
		if restoreJob.State == "pending" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if restoreJob.State != "succeeded" || restoreJob.Operation != "restore" {
		t.Fatalf("live restore did not complete: %+v", restoreJob)
	}
	originalCatalog, e1 := vmHash(filepath.Join(dir, "profiles.json"))
	restoredCatalog, e2 := vmHash(filepath.Join(restored, "profiles.json"))
	if e1 != nil || e2 != nil || originalCatalog != restoredCatalog {
		t.Fatal("live backup lost the profile catalog")
	}
	if _, err := os.Stat(filepath.Join(restored, "agent")); !os.IsNotExist(err) {
		t.Fatal("live backup included the Agent endpoint")
	}
	t.Log("installed headless Agent created and restored a live backup without runtime tokens")
	input := `{"scope":"global","operation":"set","layer":{"prepend":["DOMAIN,headless.example,DIRECT"]}}`
	c, done := context.WithTimeout(context.Background(), 30*time.Second)
	preview := vmCommand(c, agentExe, "--config-dir", dir, "preview")
	preview.Stdin = strings.NewReader(input)
	out, err := preview.CombinedOutput()
	done()
	var proposal agent.Preview
	if err != nil || json.Unmarshal(out, &proposal) != nil || proposal.ProposalID == "" {
		t.Fatalf("headless preview failed: %s %v", out, err)
	}
	if out, err = call("apply", proposal.ProposalID); err != nil {
		t.Fatalf("headless apply failed: %s %v", out, err)
	}
	// A pending proposal must never overwrite an outside edit to the rule file.
	c, done = context.WithTimeout(context.Background(), 30*time.Second)
	preview = vmCommand(c, agentExe, "--config-dir", dir, "preview")
	preview.Stdin = strings.NewReader(input)
	out, err = preview.CombinedOutput()
	done()
	if err != nil || json.Unmarshal(out, &proposal) != nil || proposal.ProposalID == "" {
		t.Fatalf("headless conflict preview failed: %s %v", out, err)
	}
	rulesFile := filepath.Join(dir, "agent-rules.json")
	oldRules, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	modifiedRules := []byte("{\"revision\":99,\"global\":{},\"future_field\":true}\n")
	if err := os.WriteFile(rulesFile, modifiedRules, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := call("apply", proposal.ProposalID); err == nil {
		t.Fatalf("headless Agent overwrote an external rules edit: %s", out)
	}
	if data, err := os.ReadFile(rulesFile); err != nil || string(data) != string(modifiedRules) {
		t.Fatal("headless Agent changed external rules edit")
	}
	var conflictStatus agent.Status
	if out, err := call("status"); err != nil || json.Unmarshal(out, &conflictStatus) != nil || conflictStatus.RewriteWarning == "" {
		t.Fatal("headless Agent omitted rules conflict warning")
	}
	if err := os.WriteFile(rulesFile, oldRules, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("installed headless Agent preserved external rules edits and reported the conflict")
	// Simulate a maliciously redirected profile path while the installed
	// headless Agent is running. Deletion must leave both the catalog and the
	// file outside the configuration directory untouched.
	outside := t.TempDir()
	external := filepath.Join(outside, "outside.yaml")
	if err := os.WriteFile(external, []byte("outside-data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "profiles", "unsafe-link")
	c, done = context.WithTimeout(context.Background(), 15*time.Second)
	linkOutput, linkErr := vmCommand(c, "cmd.exe", "/c", "mklink", "/J", link, outside).CombinedOutput()
	done()
	if linkErr != nil {
		t.Fatalf("create profile junction: %s %v", linkOutput, linkErr)
	}
	defer os.Remove(link)
	store := profile.NewStore(dir)
	original, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	modified := original
	modified.Items = append(append([]profile.CatalogItem(nil), original.Items...), profile.CatalogItem{UID: "unsafe-fixture", Name: "unsafe-fixture", Type: "local", File: filepath.Join("profiles", "unsafe-link", "outside.yaml")})
	if err := store.Save(modified); err != nil {
		t.Fatal(err)
	}
	if payload, err := call("delete-profile", "unsafe-fixture"); err == nil {
		t.Fatalf("Agent deleted junction target: %s", payload)
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != "outside-data" {
		t.Fatal("Agent changed file outside profile directory")
	}
	after, err := store.Load()
	if err != nil || len(after.Items) != len(modified.Items) {
		t.Fatal("rejected profile deletion changed catalog")
	}
	if err := store.Save(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	t.Log("installed Agent rejected profile deletion through a junction and preserved the external file")
	if out, err = call("shutdown"); err != nil {
		t.Fatalf("headless shutdown failed: %s %v", out, err)
	}
	select {
	case err := <-finished:
		stopped = true
		if err != nil {
			t.Fatalf("headless process exit: %v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("headless process did not stop")
	}
	_ = logFile.Sync()
	readyOutput, err := os.ReadFile(logFile.Name())
	if err != nil || !strings.Contains(string(readyOutput), `"ready":true`) || !strings.Contains(string(readyOutput), `"headless":true`) {
		t.Fatal("headless CLI did not emit its readiness result")
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		routes, dns, e := vmNetworkSnapshot()
		if e == nil && reflect.DeepEqual(routes, beforeRoutes) && reflect.DeepEqual(dns, beforeDNS) {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("headless shutdown did not restore routes and DNS")
}

func vmHeadlessParentExit(t *testing.T, agentExe, dir string) {
	t.Helper()
	beforeRoutes, beforeDNS, err := vmNetworkSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "headless-parent-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := vmCommand(ctx, agentExe, "--config-dir", dir, "serve")
	server.Stdout, server.Stderr = logFile, logFile
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			_ = server.Process.Kill()
			<-finished
		}
		if t.Failed() {
			_ = logFile.Sync()
			data, _ := os.ReadFile(logFile.Name())
			if len(data) > 65536 {
				data = data[len(data)-65536:]
			}
			t.Logf("headless parent-exit log: %s", data)
		}
	}()
	client := agent.Client{Dir: dir, Timeout: 3 * time.Second}
	deadline := time.Now().Add(100 * time.Second)
	var status agent.Status
	for time.Now().Before(deadline) {
		if err := client.Call(context.Background(), "status", nil, &status); err == nil && status.Headless && status.TUN && !status.TUNPending {
			break
		}
		time.Sleep(time.Second)
	}
	if !status.TUN {
		t.Fatal("headless parent-exit test did not reach TUN")
	}
	if err := server.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-finished
	reaped = true
	deadline = time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var current agent.Status
		bridgeErr := client.Call(context.Background(), "status", nil, &current)
		routes, dns, snapshotErr := vmNetworkSnapshot()
		if bridgeErr != nil && snapshotErr == nil && reflect.DeepEqual(routes, beforeRoutes) && reflect.DeepEqual(dns, beforeDNS) {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("headless child did not clean up after its launcher exited")
}

// This test exercises the shipped MSI and real Wintun only inside the isolated,
// single-disk QEMU guest; it must never run against a workstation's routes.
func TestWindowsVMEndToEnd(t *testing.T) {
	requireDisposableVM(t)
	vmAgentJunctionSafety(t)
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
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 35*time.Second)
	versionOutput, versionErr := vmCommand(versionCtx, agentExe, "version").CombinedOutput()
	versionContextErr := versionCtx.Err()
	versionCancel()
	var version struct {
		Version string `json:"version"`
	}
	if versionErr != nil || json.Unmarshal(versionOutput, &version) != nil || version.Version != netflow.Version() {
		for _, channel := range []string{"Application", "Microsoft-Windows-Windows Defender/Operational"} {
			c, done := context.WithTimeout(context.Background(), 10*time.Second)
			events, eventErr := vmCommand(c, "wevtutil.exe", "qe", channel, "/q:*[System[(EventID=1000 or EventID=1001 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119)]]", "/c:4", "/rd:true", "/f:text").CombinedOutput()
			done()
			t.Logf("recent guest %s events: %s (%v)", channel, events, eventErr)
		}
		t.Fatalf("installed CLI version differs from test manifest: %s %v, context: %v", versionOutput, versionErr, versionContextErr)
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
	for name, contents := range map[string]string{"nodes.yaml": "proxies: [{name: migrated-provider-node, type: direct}]\n", "bad.yaml": "proxies: [{name: fallback, type: direct}]\n", "rules.yaml": "payload: ['+.blocked.netflow-test.example']\n"} {
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
		"g1.yaml":    "append: [{name: Extra, type: select, proxies: [DIRECT]}, {name: FromSet, type: select, use: [imported, remote, bad]}]\n",
		"m1.yaml":    "profile: {store-selected: true}\nproxy-providers:\n  imported: {type: file, path: ./sets/nodes.yaml, health-check: {enable: false}}\n  remote: {type: http, url: 'http://10.233.42.1:18765/v1/provider.yaml', path: ./sets/remote.yaml, interval: 3600, health-check: {enable: false}}\n  bad: {type: http, url: 'http://10.233.42.1:18765/v1/missing?token=synthetic-secret', path: ./sets/bad.yaml, interval: 3600, health-check: {enable: false}}\nrule-providers:\n  blocked: {type: file, behavior: domain, format: yaml, path: ./sets/rules.yaml}\n",
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
		c, done := context.WithTimeout(context.Background(), 40*time.Second)
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
	// Keep this isolated test independent of external GeoIP download availability.
	if err := os.WriteFile(filepath.Join(migrationTarget, "Country.mmdb"), vmGeoFixture, 0600); err != nil {
		t.Fatal(err)
	}
	backupRoot := t.TempDir()
	backupArchive := filepath.Join(backupRoot, "snapshot.zip")
	backupTarget := filepath.Join(backupRoot, "restored")
	for _, step := range []struct{ dir, action string }{{migrationTarget, "backup-export"}, {backupTarget, "backup-restore"}} {
		c, done := context.WithTimeout(context.Background(), 40*time.Second)
		out, e := vmCommand(c, agentExe, "--config-dir", step.dir, step.action, backupArchive).CombinedOutput()
		done()
		if e != nil {
			t.Fatalf("installed %s failed: %s: %v", step.action, out, e)
		}
	}
	catalog, err := profile.NewStore(migrationTarget).Load()
	if err != nil || len(catalog.Items) == 0 {
		t.Fatal("missing migrated profile index")
	}
	paths := []string{"profiles.json"}
	for _, item := range catalog.Items {
		paths = append(paths, item.File)
	}
	for _, rel := range paths {
		original, e1 := vmHash(filepath.Join(migrationTarget, rel))
		restored, e2 := vmHash(filepath.Join(backupTarget, rel))
		if e1 != nil || e2 != nil || original != restored {
			t.Fatalf("installed backup lost %s", rel)
		}
	}
	originalFiles, e1 := os.ReadDir(filepath.Join(migrationTarget, "verge-imports"))
	restoredFiles, e2 := os.ReadDir(filepath.Join(backupTarget, "verge-imports"))
	if e1 != nil || e2 != nil || len(originalFiles) == 0 || len(restoredFiles) != len(originalFiles) {
		t.Fatal("installed backup lost Verge recovery archive")
	}
	for _, file := range originalFiles {
		original, e1 := vmHash(filepath.Join(migrationTarget, "verge-imports", file.Name()))
		restored, e2 := vmHash(filepath.Join(backupTarget, "verge-imports", file.Name()))
		if e1 != nil || e2 != nil || original != restored {
			t.Fatal("installed backup changed Verge recovery archive")
		}
	}
	t.Log("installed CLI backed up and restored the migrated configuration to a new directory")
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
		// The kernel starts during Prepare, before the desktop window and Agent
		// bridge are ready. DNS success alone is not an Agent readiness signal.
		var out []byte
		agentDeadline := time.Now().Add(30 * time.Second)
		attempts := 0
		for time.Now().Before(agentDeadline) {
			attempts++
			commandCtx, commandCancel := context.WithTimeout(context.Background(), 5*time.Second)
			out, err = vmCommand(commandCtx, agentExe, "--config-dir", migrationTarget, "groups").CombinedOutput()
			commandCancel()
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			data, _ := os.ReadFile(filepath.Join(migrationTarget, "migration-gui.log"))
			entries, listErr := os.ReadDir(filepath.Join(migrationTarget, "agent"))
			t.Fatalf("migrated groups query failed after %d attempts: %s: %v; endpoint count %d (%v); GUI log: %s", attempts, out, err, len(entries), listErr, data)
		}
		if attempts > 1 {
			t.Logf("Agent became ready after %d read-only groups attempts", attempts)
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
			c, done := context.WithTimeout(context.Background(), 40*time.Second)
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
		out, err = callMigration("providers")
		var providers agent.ProviderList
		if err != nil || json.Unmarshal(out, &providers) != nil {
			t.Fatalf("provider list failed: %s %v", out, err)
		}
		remoteFound := false
		for _, p := range providers.Proxy {
			if p.Name == "remote" && p.Vehicle == "HTTP" {
				remoteFound = true
			}
		}
		if !remoteFound {
			t.Fatalf("remote provider missing: %s", out)
		}
		if strings.Contains(string(out), "10.233.42.1") {
			t.Fatal("provider listing exposed its URL")
		}
		if out, err := callMigration("update-provider", "proxy", "missing"); err == nil {
			t.Fatalf("unknown provider update accepted: %s", out)
		}
		out, err = callMigration("update-provider", "proxy", "remote")
		var job agent.ProviderJob
		if err != nil || json.Unmarshal(out, &job) != nil || job.JobID == "" {
			t.Fatalf("provider job failed to start: %s %v", out, err)
		}
		deadline = time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			out, err = callMigration("provider-job-status", job.JobID)
			if err == nil {
				err = json.Unmarshal(out, &job)
			}
			if err == nil && job.State != "pending" {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if err != nil || job.State != "succeeded" {
			t.Fatalf("provider job did not succeed: %+v %v", job, err)
		}
		out, err = callMigration("update-provider", "proxy", "bad")
		if err != nil || json.Unmarshal(out, &job) != nil || job.JobID == "" {
			t.Fatalf("failing provider job did not start: %s %v", out, err)
		}
		deadline = time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			out, err = callMigration("provider-job-status", job.JobID)
			if err == nil {
				err = json.Unmarshal(out, &job)
			}
			if err == nil && job.State != "pending" {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if err != nil || job.State != "failed" || job.Error == "" || strings.Contains(string(out), "synthetic-secret") || strings.Contains(string(out), "10.233.42.1") {
			t.Fatalf("provider failure was not safely reported: %+v %v", job, err)
		}
		t.Log("installed Agent listed and updated a migrated HTTP provider while TUN was active")
		out, err = callMigration("groups")
		if err != nil || !strings.Contains(string(out), "migrated-provider-node") {
			t.Fatalf("migrated provider unavailable in TUN: %s %v", out, err)
		}
		out, err = callMigration("rules")
		if err != nil || !strings.Contains(string(out), "blocked") {
			t.Fatalf("migrated rule provider unavailable in TUN: %s %v", out, err)
		}
		preview := func() ([]byte, error) {
			c, done := context.WithTimeout(context.Background(), 40*time.Second)
			defer done()
			cmd := vmCommand(c, agentExe, "--config-dir", migrationTarget, "preview")
			cmd.Stdin = strings.NewReader(`{"scope":"global","operation":"set","layer":{"prepend":["DOMAIN,agent.netflow-test.example,DIRECT"]}}`)
			return cmd.CombinedOutput()
		}
		out, err = preview()
		var proposal agent.Preview
		if err != nil || json.Unmarshal(out, &proposal) != nil || proposal.ProposalID == "" {
			// Diagnose only synthetic data in this disposable guest. Do not print
			// subscriptions, provider contents, URLs, or absolute paths.
			catalog, e := profile.NewStore(migrationTarget).Load()
			if e == nil && len(catalog.Items) == 1 {
				item := catalog.Items[0]
				if archive, pathErr := migration.ArchivePath(migrationTarget, item.Option.VergeArchive); pathErr == nil {
					rel, relErr := filepath.Rel(migrationTarget, archive)
					resolved, resolveErr := filepath.EvalSymlinks(migrationTarget)
					t.Logf("archive path diagnostic: lexicalLocal=%t rootMatchesResolved=%t relativeErr=%v resolveErr=%v", relErr == nil && filepath.IsLocal(rel), strings.EqualFold(filepath.Clean(resolved), filepath.Clean(migrationTarget)), relErr, resolveErr)
				}
				body, readErr := os.ReadFile(filepath.Join(migrationTarget, "config.yaml"))
				if readErr == nil && item.Option.VergeExtensions {
					body, _, _, readErr = migration.ComposeArchived(migrationTarget, item.Option.VergeArchive, item.Option.VergeUID, body)
				}
				if readErr == nil {
					body, readErr = profile.RemapVergeProviders(body, item.Option.VergeProviderPaths)
				}
				if readErr == nil {
					request, _ := json.Marshal(validation.Request{Directory: migrationTarget, Configs: []validation.Config{{ID: item.UID, Body: body}}})
					c, done := context.WithTimeout(context.Background(), 25*time.Second)
					cmd := vmCommand(c, filepath.Join(install, "NetFlow.exe"), "--internal-validate")
					cmd.Stdin = strings.NewReader(string(request))
					data, validationErr := cmd.CombinedOutput()
					done()
					var diagnostic validation.Result
					if validationErr == nil && json.Unmarshal(data, &diagnostic) == nil {
						root, rootErr := os.OpenRoot(migrationTarget)
						if rootErr == nil {
							for path, expected := range diagnostic.Sources {
								actual, hashErr := validation.HashSource(root, migrationTarget, path)
								if hashErr != nil && !(errors.Is(hashErr, os.ErrNotExist) && expected == ([32]byte{})) || hashErr == nil && actual != expected {
									t.Logf("validation source mismatch: %s err=%v expectedMissing=%t", filepath.Base(path), hashErr, expected == ([32]byte{}))
								}
							}
							_ = root.Close()
						}
					} else {
						t.Logf("independent validator failed: %v", validationErr)
					}
				}
			}
			t.Fatalf("TUN offline agent preview failed: %s %v", out, err)
		}
		catalog, err := profile.NewStore(migrationTarget).Load()
		if err != nil || len(catalog.Items) != 1 {
			t.Fatalf("migration catalog: %v", err)
		}
		managed := catalog.Items[0].Option.VergeProviderPaths["./sets/rules.yaml"]
		if managed == "" {
			t.Fatal("migrated rule provider path missing")
		}
		managedPath := filepath.Join(migrationTarget, filepath.FromSlash(managed))
		if err := os.WriteFile(managedPath, []byte("payload: ['+.changed.netflow-test.example']\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := callMigration("apply", proposal.ProposalID); err == nil {
			t.Fatalf("stale provider proposal accepted: %s", out)
		}
		if err := os.WriteFile(managedPath, []byte("invalid: true\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := preview(); err == nil {
			t.Fatalf("invalid rule provider accepted: %s", out)
		}
		if err := os.WriteFile(managedPath, []byte("payload: ['+.blocked.netflow-test.example']\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Log("installed agent checked provider contents offline and rejected stale TUN proposal")
		var large strings.Builder
		large.WriteString("payload:\n")
		for i := 0; i < 100000; i++ {
			fmt.Fprintf(&large, "  - '+.d%d.netflow-test.example'\n", i)
		}
		if err := os.WriteFile(managedPath, []byte(large.String()), 0600); err != nil {
			t.Fatal(err)
		}
		type previewResult struct {
			out []byte
			err error
		}
		previewDone := make(chan previewResult, 1)
		go func() { out, err := preview(); previewDone <- previewResult{out, err} }()
		time.Sleep(250 * time.Millisecond)
		start := time.Now()
		out, err = callMigration("status")
		if err != nil || time.Since(start) > 5*time.Second {
			t.Fatalf("agent status blocked during validation: %s %v", out, err)
		}
		select {
		case result := <-previewDone:
			if result.err != nil {
				t.Fatalf("large preview failed: %s %v", result.out, result.err)
			}
			t.Log("large preview completed before the responsiveness check")
		default:
			result := <-previewDone
			if result.err != nil {
				t.Fatalf("large preview failed: %s %v", result.out, result.err)
			}
			t.Log("agent status remained responsive during offline validation")
		}
		if err := os.WriteFile(managedPath, []byte("payload: ['+.blocked.netflow-test.example']\n"), 0600); err != nil {
			t.Fatal(err)
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
	vmHeadlessRoundTrip(t, agentExe, backupTarget)
	t.Log("installed headless CLI activated TUN, applied a rewrite without visible windows, and restored networking on shutdown")
	vmHeadlessParentExit(t, agentExe, backupTarget)
	t.Log("headless child restored networking after its CLI launcher was forcibly terminated")
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
	// Simulate an update downloaded before shutdown. The installed GUI must
	// apply it before the kernel can map the database, then remove the pending
	// transaction. The fixture is a synthetic MaxMind test database.
	oldGeo := []byte("previous database")
	if err := os.WriteFile(filepath.Join(dir, "Country.mmdb"), oldGeo, 0600); err != nil {
		t.Fatal(err)
	}
	pendingDir := filepath.Join(dir, geoupdate.PendingDirectory)
	if err := os.Mkdir(pendingDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDir, "item-0"), vmGeoFixture, 0600); err != nil {
		t.Fatal(err)
	}
	beforeGeo, afterGeo := sha256.Sum256(oldGeo), sha256.Sum256(vmGeoFixture)
	geoManifest := fmt.Sprintf(`{"version":1,"items":[{"name":"Country.mmdb","kind":"mmdb","before":"%x","after":"%x","payload":"item-0"}]}`, beforeGeo, afterGeo)
	if err := os.WriteFile(filepath.Join(pendingDir, "manifest.json"), []byte(geoManifest), 0600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\nmode: rule\nprofile: {store-fake-ip: true}\ndns:\n  enable: true\n  listen: '%s'\n  enhanced-mode: fake-ip\n  nameserver: ['%s']\ntun:\n  enable: false\n  stack: system\n  auto-route: true\n  auto-detect-interface: true\nrules:\n  - MATCH,REJECT\n", dnsAddress, packet.LocalAddr().String())
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	legacyPrefs, err := json.Marshal(map[string]any{"SilentStart": true, "WebDAVURL": "https://user:synthetic-url-secret@backup.invalid/?token=synthetic-token", "WebDAVUser": "synthetic-user", "WebDAVPassword": "synthetic-vm-secret", "FuturePreference": "preserved"})
	if err != nil {
		t.Fatal(err)
	}
	settingsBody, err := json.Marshal(map[string]string{"prefs": string(legacyPrefs)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), settingsBody, 0600); err != nil {
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
		c, done := context.WithTimeout(context.Background(), 40*time.Second)
		defer done()
		out, err := vmCommand(c, agentExe, append([]string{"--config-dir", dir}, args...)...).CombinedOutput()
		if contextErr := c.Err(); contextErr != nil {
			return out, fmt.Errorf("CLI command timed out: %w", contextErr)
		}
		return out, err
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
	settingsBody, err = os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil || strings.Contains(string(settingsBody), "synthetic-vm-secret") || strings.Contains(string(settingsBody), "synthetic-url-secret") || strings.Contains(string(settingsBody), "synthetic-token") || strings.Contains(string(settingsBody), "synthetic-user") {
		t.Fatal("legacy credential remained in the installed settings")
	}
	var savedSettings struct {
		Prefs string `json:"prefs"`
	}
	var savedPrefs map[string]json.RawMessage
	if json.Unmarshal(settingsBody, &savedSettings) != nil || json.Unmarshal([]byte(savedSettings.Prefs), &savedPrefs) != nil || len(savedPrefs["FuturePreference"]) == 0 {
		t.Fatal("credential migration lost settings")
	}
	var protected string
	if json.Unmarshal(savedPrefs[webDAVProtectedKey], &protected) != nil {
		t.Fatal("protected credential missing")
	}
	if plain, err := unprotectWebDAV(protected); err != nil || plain.Password != "synthetic-vm-secret" || plain.User != "synthetic-user" || !strings.Contains(plain.URL, "synthetic-url-secret") {
		t.Fatal("protected credential cannot be recovered by the guest user")
	}
	t.Log("installed GUI protected a legacy credential without losing unrelated settings")
	updatedGeo, geoErr := os.ReadFile(filepath.Join(dir, "Country.mmdb"))
	if geoErr != nil || sha256.Sum256(updatedGeo) != afterGeo {
		t.Fatalf("installed GUI did not apply pending GeoData: %v", geoErr)
	}
	if _, geoErr := os.Stat(pendingDir); !errors.Is(geoErr, os.ErrNotExist) {
		t.Fatalf("pending GeoData transaction remains: %v", geoErr)
	}
	if out, err := call("update-geo"); err != nil {
		t.Fatalf("GeoData update request failed: %s %v", out, err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s, err = status()
		if err == nil && !s.GeoPending && s.GeoError != "" {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || s.GeoPending || !strings.Contains(s.GeoError, "混合代理") || s.GeoRestart {
		t.Fatalf("GeoData update status: %+v %v", s, err)
	}
	t.Log("installed GUI applied a pending GeoData database and Agent reported the missing-proxy failure")
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
	junctionTUN, err := tun.Compose([]byte(junctionConfig), true, "NetFlowVM")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workerDir, "config.yaml"), junctionTUN, 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(workerDir); err != nil {
		t.Fatalf("start junction provider: %v", err)
	}
	if !worker.Status().TUN {
		t.Fatal("junction-cache test did not start TUN")
	}
	if err := worker.UpdateProxyProvider("linked"); err == nil {
		t.Fatal("junction cache update claimed it was safely persisted")
	}
	if err := worker.Stop(); err != nil {
		t.Fatalf("stop junction provider: %v", err)
	}
	waitRestored("junction cache failure")
	if worker.CacheWarning() == "" {
		t.Fatal("junction cache failure was not reported")
	}
	afterProvider, err := os.ReadFile(provider)
	if err != nil || string(afterProvider) != string(originalProvider) {
		t.Fatalf("provider update followed unprivileged junction: %v", err)
	}
	t.Log("provider update did not follow a junction in the user's directory")
	if err := os.Mkdir(filepath.Join(workerDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	remoteProxy := filepath.Join(workerDir, "providers", "remote.yaml")
	remoteRule := filepath.Join(workerDir, "providers", "remote-rules.yaml")
	if err := os.WriteFile(remoteProxy, []byte("proxies: [{name: old, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(remoteRule, []byte("payload:\n  - '+.old.netflow-test.example'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	remoteConfig := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\n" +
		"proxy-providers:\n  remote: {type: http, url: 'http://10.233.42.1:18765/v1/provider.yaml', path: providers/remote.yaml, interval: 3600, health-check: {enable: false}}\n" +
		"rule-providers:\n  remote: {type: http, url: 'http://10.233.42.1:18765/v1/rules.yaml', path: providers/remote-rules.yaml, behavior: domain, format: yaml, interval: 1}\n" +
		"rules: ['RULE-SET,remote,DIRECT', 'MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(workerDir, "config.yaml"), []byte(remoteConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(workerDir); err != nil {
		t.Fatalf("start HTTP provider worker: %v", err)
	}
	if err := worker.UpdateProxyProvider("remote"); err != nil {
		t.Fatalf("persist manual proxy update: %v", err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range worker.RuleProviders() {
			if p.Name == "remote" && p.Count == 2 {
				goto ruleRefreshed
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("automatic rule provider did not refresh")
ruleRefreshed:
	if err := worker.Stop(); err != nil {
		t.Fatalf("stop HTTP provider worker: %v", err)
	}
	for path, marker := range map[string]string{remoteProxy: "name: remote", remoteRule: "+.fresh.netflow-test.example"} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), marker) {
			t.Fatalf("provider update not persisted: %q %v", data, err)
		}
	}
	t.Log("manual proxy and automatic rule provider updates persisted outside the privileged stage")
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
	failedGeoDir := filepath.Join(memoryDir, geoupdate.PendingDirectory)
	if err := os.Mkdir(failedGeoDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(failedGeoDir, "manifest.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
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
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		out, err := vmCommand(ctx, agentExe, append([]string{"--config-dir", memoryDir}, args...)...).CombinedOutput()
		if contextErr := ctx.Err(); contextErr != nil {
			return out, fmt.Errorf("CLI command timed out: %w", contextErr)
		}
		return out, err
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
	if s.GeoError == "" || s.GeoRestart {
		t.Fatalf("failed startup GeoData update not reported: %+v", s)
	}
	if _, err := os.Stat(failedGeoDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed GeoData transaction was not quarantined: %v", err)
	}
	t.Log("Agent reported a failed startup GeoData update and its transaction was quarantined")
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
