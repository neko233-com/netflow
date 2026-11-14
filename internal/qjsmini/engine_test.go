package qjsmini

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBasicABI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := Eval(ctx, `JSON.stringify({answer:42})`, 1000)
	if err != nil || string(out) != `{"answer":42}` {
		t.Fatalf("ABI: %s %v", out, err)
	}
}
func TestGuestCannotAccessHostFilesystemOrEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "canary.txt"), []byte("synthetic-sensitive"), 0600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("NETFLOW_SCRIPT_TEST_SECRET", "synthetic-secret")
	// A default mount of the host working directory would reveal this file.
	code := `JSON.stringify({file:std.loadFile('/canary.txt'),env:std.getenv('NETFLOW_SCRIPT_TEST_SECRET')})`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := Eval(ctx, code, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"file":null}` && string(out) != `{"file":null,"env":null}` {
		t.Fatalf("guest accessed host data: %s", out)
	}
}
func TestGuestLinearMemoryHasHardCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := eval(ctx, `(()=>{try {new Uint8Array(512 * 1024 * 1024);return "allocated"} catch(e){return "blocked"}})()`, 0, 1000, time.Unix(0, 0))
	if err == nil && string(out) != "blocked" {
		t.Fatalf("guest allocated beyond memory cap: %s", out)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("allocation test hit the time limit instead of the memory limit")
	}
}

func TestGuestOutputLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Eval(ctx, `"abcdef"`, 3); !errors.Is(err, ErrOutput) {
		t.Fatalf("oversized output accepted: %v", err)
	}
}
