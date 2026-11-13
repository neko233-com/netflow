//go:build integration

package sysproxy

import (
	"os"
	"runtime"
	"testing"
)

// TestLiveSystemProxy changes the macOS system proxy. It is not part of
// the default test set. Set CLASHGO_LIVE_SYSPROXY=1 on a Mac to run it.
func TestLiveSystemProxy(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("CLASHGO_LIVE_SYSPROXY") != "1" {
		t.Skip("set CLASHGO_LIVE_SYSPROXY=1 on macOS to change the system proxy")
	}
	s := NewSystem()
	prev, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Set(prev) })
	next := Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}
	if err := s.Set(next); err != nil {
		t.Fatal(err)
	}
	got, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.HTTP != next.HTTP {
		t.Fatalf("current %+v", got)
	}
}
