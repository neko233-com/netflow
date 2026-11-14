//go:build windows

package vmverify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyMediaRejectsAlteredFilesAndWrongRun(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 32)
	m := manifest{ID: id, Files: make(map[string]artifact)}
	if err := os.WriteFile(filepath.Join(root, "media-id.txt"), []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netflow-app.test.exe", "NetFlow.msi"} {
		data := []byte("verified " + name)
		sum := sha256.Sum256(data)
		m.Files[name] = artifact{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyMedia(root, m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "NetFlow.msi"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyMedia(root, m); err == nil {
		t.Fatal("accepted altered media")
	}
	if err := os.WriteFile(filepath.Join(root, "media-id.txt"), []byte(strings.Repeat("b", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyMedia(root, m); err == nil {
		t.Fatal("accepted media from a different run")
	}
}

func TestLegacyAutostartCommandMatchesOnlyOwnedPaths(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`E:\netflow-vm-agent.exe`, true},
		{`"D:\netflow-vm-agent.exe"`, true},
		{`C:\OEM\netflow-vm-agent.exe`, true},
		{`D:\OEM\netflow-vm-agent.exe`, false},
		{`E:\other\netflow-vm-agent.exe`, false},
		{`E:\netflow-vm-agent.exe --other`, false},
		{`C:\unrelated.exe`, false},
	} {
		if got := legacyAutostartCommand(tc.command, "C:"); got != tc.want {
			t.Errorf("legacyAutostartCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestRedactOutput(t *testing.T) {
	input := `failure HTTPS://user:pass@example.test/path?token=secret and "https://other.test/file?sig=abc" diagnostic`
	want := `failure [URL redacted] and "[URL redacted]" diagnostic`
	if got := redactOutput(input); got != want {
		t.Fatalf("redactOutput() = %q, want %q", got, want)
	}
	input = `escaped https://example.test/a?token=secret\" after`
	want = `escaped [URL redacted]\" after`
	if got := redactOutput(input); got != want {
		t.Fatalf("redactOutput() = %q, want %q", got, want)
	}
}
