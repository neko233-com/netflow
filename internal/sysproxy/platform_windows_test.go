//go:build windows

package sysproxy

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The test uses an isolated registry key; it never changes Windows proxy settings.
func TestWindowsProxyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := `Software\NetFlowTests\` + filepath.Base(dir)
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close(); _ = registry.DeleteKey(registry.CURRENT_USER, keyPath) })
	before := map[string]proxyValue{
		"ProxyEnable":   {Exists: true, Type: registry.DWORD, Number: 1},
		"ProxyServer":   {Exists: true, Type: registry.SZ, Text: "old-proxy:1234"},
		"ProxyOverride": {Exists: true, Type: registry.EXPAND_SZ, Text: "%LOCALAPPDATA%"},
		"AutoConfigURL": {Exists: true, Type: registry.SZ, Text: "https://example.org/proxy.pac"},
	}
	for name, value := range before {
		if err := writeProxyValue(k, name, value); err != nil {
			t.Fatal(err)
		}
	}
	backup := filepath.Join(dir, "backup.json")
	s := &windowsSystem{keyPath: keyPath, backupFile: backup, notify: func() {}}
	if err := s.Set(Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatal(err)
	}
	if v, err := readProxyValue(k, "AutoConfigURL"); err != nil || v.Exists {
		t.Fatalf("PAC not disabled: %+v %v", v, err)
	}
	// The backup can also be restored by a new process after a crash.
	s = &windowsSystem{keyPath: keyPath, backupFile: backup, notify: func() {}}
	if err := s.Restore(); err != nil {
		t.Fatal(err)
	}
	for name, want := range before {
		got, err := readProxyValue(k, name)
		if err != nil || got != want {
			t.Errorf("%s: got %+v (%v), want %+v", name, got, err, want)
		}
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup remains: %v", err)
	}
}

func TestWindowsProxyDoesNotOverwriteOtherApp(t *testing.T) {
	dir := t.TempDir()
	keyPath := `Software\NetFlowTests\` + filepath.Base(dir)
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close(); _ = registry.DeleteKey(registry.CURRENT_USER, keyPath) })
	s := &windowsSystem{keyPath: keyPath, backupFile: filepath.Join(dir, "backup.json"), notify: func() {}}
	if err := s.Set(Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue("ProxyServer", "other-app:8080"); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(); err == nil {
		t.Fatal("restored over a different proxy")
	}
	if got, _, err := k.GetStringValue("ProxyServer"); err != nil || got != "other-app:8080" {
		t.Fatalf("proxy changed: %q %v", got, err)
	}
	if _, err := os.Stat(s.backupFile); err != nil {
		t.Fatalf("backup lost: %v", err)
	}
}
