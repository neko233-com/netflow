//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func junction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.Command("pwsh", "-NoProfile", "-Command", "New-Item -ItemType Junction -Path $env:NETFLOW_TEST_LINK -Target $env:NETFLOW_TEST_TARGET | Out-Null")
	cmd.Env = append(os.Environ(), "NETFLOW_TEST_LINK="+link, "NETFLOW_TEST_TARGET="+target)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction: %s %v", output, err)
	}
}

func TestAgentRejectsJunctionAndPinsEndpointDirectory(t *testing.T) {
	base := t.TempDir()
	actual, alias := filepath.Join(base, "actual"), filepath.Join(base, "alias")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(alias, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := Start(actual, func(context.Context, string, json.RawMessage) (any, error) { return map[string]bool{"ok": true}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	junction(t, filepath.Join(alias, "agent"), filepath.Join(actual, "agent"))
	if _, err := Start(alias, func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }); err == nil {
		t.Fatal("Agent start followed a junction")
	}
	if err := (Client{Dir: alias}).Call(context.Background(), "status", nil, nil); err == nil {
		t.Fatal("Agent discovery followed a junction")
	}
	var response map[string]bool
	if err := (Client{Dir: actual}).Call(context.Background(), "status", nil, &response); err != nil || !response["ok"] {
		t.Fatalf("original Agent affected: %v", err)
	}
	saved := filepath.Join(actual, "saved-agent")
	if err := os.Rename(filepath.Join(actual, "agent"), saved); err != nil {
		t.Skipf("renaming an open directory is unavailable: %v", err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(b.file)
	if err := os.WriteFile(filepath.Join(outside, name), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(actual, "agent"), outside)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, name)); err != nil || string(data) != "outside" {
		t.Fatal("close touched outside file")
	}
	if _, err := os.Stat(filepath.Join(saved, name)); !os.IsNotExist(err) {
		t.Fatal("original endpoint was not removed")
	}
}
