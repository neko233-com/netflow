//go:build windows

// netflow-vm-agent runs only inside the disposable Windows validation guest.
// It polls a private QEMU slirp endpoint for a fixed test executable and MSI.
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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
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

var httpClient = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

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
	if !validHex(m.ID, 32) || len(m.Files) != 2 || len(m.Expected) != 3 {
		return m, errors.New("invalid manifest")
	}
	for _, name := range []string{"netflow-app.test.exe", "NetFlow.msi"} {
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
func acquire(dir, name string, a artifact) (string, error) {
	ext := filepath.Ext(name)
	path := filepath.Join(dir, a.SHA256+ext)
	if sum, n, err := digestFile(path); err == nil && sum == a.SHA256 && n == a.Size {
		return path, nil
	}
	resp, err := httpClient.Get(base + "/v1/files/" + name)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("artifact unavailable")
	}
	file, err := os.CreateTemp(dir, "artifact-*.partial")
	if err != nil {
		return "", err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(file, h), io.LimitReader(resp.Body, a.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("artifact digest mismatch")
	}
	// Destination is a content-addressed file under this application's cache.
	_ = os.Remove(path)
	if err = os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

type cappedBuffer struct{ bytes.Buffer }

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
func execute(m manifest, dir string) result {
	out := result{ID: m.ID}
	exe, err := acquire(dir, "netflow-app.test.exe", m.Files["netflow-app.test.exe"])
	if err != nil {
		out.Error = err.Error()
		return out
	}
	msi, err := acquire(dir, "NetFlow.msi", m.Files["NetFlow.msi"])
	if err != nil {
		out.Error = err.Error()
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestWindowsVMEndToEnd$", "-test.timeout=10m")
	hashes, _ := json.Marshal(m.Expected)
	cmd.Env = append(os.Environ(), "NETFLOW_WINDOWS_VM=1", "NETFLOW_VM_MSI="+msi, "NETFLOW_VM_EXPECTED="+string(hashes), "GOMAXPROCS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	var output cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	out.Output = output.String()
	if err != nil {
		out.Error = err.Error()
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
func main() {
	// Setup initially logs in with UAC disabled. The OEM bootstrap enables it
	// and reboots; do not run the test until this process has a filtered token.
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	root := filepath.Join(os.Getenv("LOCALAPPDATA"), "NetFlowVMVerify")
	if !filepath.IsAbs(root) || os.MkdirAll(root, 0700) != nil {
		return
	}
	for {
		m, err := getManifest()
		if err == nil {
			marker := filepath.Join(root, "result-"+m.ID+".json")
			var r result
			if data, e := os.ReadFile(marker); e == nil && len(data) < 2*1024*1024 && json.Unmarshal(data, &r) == nil && r.ID == m.ID {
				_ = post(r)
			} else {
				r = execute(m, root)
				data, _ := json.Marshal(r)
				_ = os.WriteFile(marker, data, 0600)
				_ = post(r)
			}
		}
		time.Sleep(3 * time.Second)
	}
}
