package core

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDisabledExternalControllerStaysClosedOnReload(t *testing.T) {
	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nexternal-controller: %s\nsecret: test-secret\nrules: ['MATCH,DIRECT']\n", addr)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.DisableExternalController()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	for i := 0; i < 2; i++ {
		if i == 1 {
			if err := c.Reload(); err != nil {
				t.Fatal(err)
			}
		}
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			t.Fatal("disabled controller accepted a connection")
		}
	}
}

func TestExternalControllerListens(t *testing.T) {
	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nexternal-controller: %s\nsecret: test-secret\nrules:\n  - MATCH,DIRECT\n", addr)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	if err := waitListen(addr); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	for _, tc := range []struct {
		secret string
		status int
	}{{"", http.StatusUnauthorized}, {"test-secret", http.StatusOK}} {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.secret != "" {
			req.Header.Set("Authorization", "Bearer "+tc.secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("controller status = %d, want %d", resp.StatusCode, tc.status)
		}
	}
}

func TestSafeController(t *testing.T) {
	for _, tc := range []struct {
		addr, secret string
		want         bool
	}{
		{"127.0.0.1:9097", "secret", true},
		{"[::1]:9097", "secret", true},
		{"127.0.0.1:9097", "", false},
		{"0.0.0.0:9097", "secret", false},
		{"192.168.1.1:9097", "secret", false},
		{"localhost:9097", "secret", false},
	} {
		if got := safeController(tc.addr, tc.secret); got != tc.want {
			t.Errorf("safeController(%q, ...)= %v", tc.addr, got)
		}
	}
}
