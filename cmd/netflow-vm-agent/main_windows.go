//go:build windows

// netflow-vm-agent runs only inside the disposable Windows validation guest.
// It verifies a fixed test executable and MSI on read-only QEMU media.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const base = "http://10.233.42.1:18765"
const maxArtifact = 512 << 20

type artifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type manifest struct {
	ID       string              `json:"id"`
	Files    map[string]artifact `json:"files"`
	Expected map[string]string   `json:"expected"`
}
type result struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}
func getManifest() (manifest, error) {
	var m manifest
	resp, err := httpClient.Get(base + "/v1/manifest")
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return m, errors.New("manifest unavailable")
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16384))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil {
		return m, err
	}
	if !validHex(m.ID, 32) || len(m.Files) != 3 || len(m.Expected) != 3 {
		return m, errors.New("invalid manifest")
	}
	for _, name := range []string{"netflow-app.test.exe", "NetFlow.msi", "netflow-vm-agent.exe"} {
		f, ok := m.Files[name]
		if !ok || !validHex(f.SHA256, 64) || f.Size <= 0 || f.Size > maxArtifact {
			return m, errors.New("invalid artifact metadata")
		}
	}
	for _, name := range []string{"NetFlow.exe", "netflow-agent.exe", "netflow-kernel-worker.exe"} {
		if !validHex(m.Expected[name], 64) {
			return m, errors.New("invalid expected binary hash")
		}
	}
	return m, nil
}
func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func findMedia(m manifest) (string, error) {
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		return "", err
	}
	var found string
	for i := 0; i < 26; i++ {
		if drives&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		name, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(name) != windows.DRIVE_CDROM {
			continue
		}
		id, err := os.ReadFile(filepath.Join(root, "media-id.txt"))
		if err != nil || string(id) != m.ID {
			continue
		}
		if found != "" {
			return "", errors.New("multiple matching validation media")
		}
		found = root
	}
	if found == "" {
		return "", errors.New("validation media unavailable")
	}
	if err := verifyMedia(found, m); err != nil {
		return "", err
	}
	return found, nil
}
func verifyMedia(root string, m manifest) error {
	id, err := os.ReadFile(filepath.Join(root, "media-id.txt"))
	if err != nil || string(id) != m.ID {
		return errors.New("validation media identity mismatch")
	}
	for _, name := range []string{"netflow-app.test.exe", "NetFlow.msi", "netflow-vm-agent.exe"} {
		a := m.Files[name]
		sum, size, err := digestFile(filepath.Join(root, name))
		if err != nil || sum != a.SHA256 || size != a.Size {
			return errors.New("validation media digest mismatch")
		}
	}
	return nil
}

type cappedBuffer struct{ bytes.Buffer }

// Logs can contain signed download URLs; never send them to the host bridge.
var loggedURL = regexp.MustCompile(`(?i)https?://[^\s"\\<>]+`)

func redactOutput(s string) string {
	return loggedURL.ReplaceAllString(s, "[URL redacted]")
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remain := 256*1024 - b.Len(); remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
func execute(m manifest, media string) result {
	out := result{ID: m.ID}
	exe := filepath.Join(media, "netflow-app.test.exe")
	msi := filepath.Join(media, "NetFlow.msi")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestWindowsVMEndToEnd$", "-test.timeout=10m")
	hashes, _ := json.Marshal(m.Expected)
	cmd.Env = append(os.Environ(), "NETFLOW_WINDOWS_VM=1", "NETFLOW_VM_MSI="+msi, "NETFLOW_VM_EXPECTED="+string(hashes), "GOMAXPROCS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	var output cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	out.Output = redactOutput(output.String())
	if err != nil {
		out.Error = redactOutput(err.Error())
		return out
	}
	out.OK = true
	return out
}
func post(r result) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(base+"/v1/result", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("result rejected: %s", resp.Status)
	}
	return nil
}
func event(name string) {
	resp, err := httpClient.Post(base+"/v1/event", "text/plain", strings.NewReader(name))
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Only remove our exact legacy startup command, never an arbitrary Run value.
func legacyAutostartCommand(value, systemDrive string) bool {
	args, err := windows.DecomposeCommandLine(value)
	if err != nil || len(args) != 1 || !filepath.IsAbs(args[0]) {
		return false
	}
	name := filepath.Clean(args[0])
	drive := filepath.VolumeName(name)
	return len(drive) == 2 && (strings.EqualFold(name, drive+`\netflow-vm-agent.exe`) || strings.EqualFold(drive, systemDrive) && strings.EqualFold(name, drive+`\OEM\netflow-vm-agent.exe`))
}

func removeLegacyAutostart() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	value, _, err := k.GetStringValue("NetFlowVMVerify")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !legacyAutostartCommand(value, os.Getenv("SystemDrive")) {
		return nil
	}
	return k.DeleteValue("NetFlowVMVerify")
}
func qemuGuest() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	manufacturer, _, err := k.GetStringValue("SystemManufacturer")
	_ = k.Close()
	return err == nil && strings.Contains(strings.ToLower(manufacturer), "qemu")
}
func disposableGuest() bool {
	if !qemuGuest() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wmic.exe", "diskdrive", "get", "model", "/value")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	count, matches := 0, false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(line, "\x00", "")))
		if strings.HasPrefix(line, "model=") {
			count++
			matches = strings.Contains(line, "qemu")
		}
	}
	return count == 1 && matches
}
func main() {
	if !qemuGuest() {
		return
	}
	// First-logon setup runs elevated and reboots before verification.
	if windows.GetCurrentProcessToken().IsElevated() {
		event("agent-elevated")
		return
	}
	// This event only tells the isolated host that the media executable has
	// started; no testing or system changes occur before the full disk check.
	event("media-agent-starting")
	deadline := time.Now().Add(3 * time.Minute)
	for !disposableGuest() {
		if time.Now().After(deadline) {
			event("media-agent-refused")
			return
		}
		time.Sleep(3 * time.Second)
	}
	event("agent-ready")
	cleanupErr := removeLegacyAutostart()
	root := filepath.Join(os.Getenv("LOCALAPPDATA"), "NetFlowVMVerify")
	if !filepath.IsAbs(root) || os.MkdirAll(root, 0700) != nil {
		return
	}
	for {
		m, err := getManifest()
		if err == nil {
			if cleanupErr != nil {
				_ = post(result{ID: m.ID, Error: "cannot remove legacy validation startup: " + cleanupErr.Error()})
				return
			}
			mutexName, e := windows.UTF16PtrFromString(`Local\NetFlowVMVerify-` + m.ID)
			if e != nil {
				return
			}
			mutex, e := windows.CreateMutex(nil, true, mutexName)
			if e != nil {
				if mutex != 0 {
					_ = windows.CloseHandle(mutex)
				}
				return
			}
			defer windows.CloseHandle(mutex)
			defer windows.ReleaseMutex(mutex)
			var media string
			mediaDeadline := time.Now().Add(2 * time.Minute)
			for {
				media, e = findMedia(m)
				if e == nil {
					break
				}
				if time.Now().After(mediaDeadline) {
					_ = post(result{ID: m.ID, Error: e.Error()})
					return
				}
				time.Sleep(3 * time.Second)
			}
			event("media-agent-ready")
			marker := filepath.Join(root, "result-"+m.ID+".json")
			var r result
			if data, e := os.ReadFile(marker); e == nil && len(data) < 2*1024*1024 && json.Unmarshal(data, &r) == nil && r.ID == m.ID {
			} else {
				event("test-start")
				r = execute(m, media)
				event("test-finished")
				data, _ := json.Marshal(r)
				_ = os.WriteFile(marker, data, 0600)
			}
			for attempt := 0; attempt < 12; attempt++ {
				if post(r) == nil {
					return
				}
				time.Sleep(5 * time.Second)
			}
			return
		}
		time.Sleep(3 * time.Second)
	}
}
