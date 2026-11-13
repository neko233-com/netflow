//go:build windows

package main

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
	for _, name := range []string{"netflow-app.test.exe", "NetFlow.msi", "netflow-vm-agent.exe"} {
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
