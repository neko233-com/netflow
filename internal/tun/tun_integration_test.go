//go:build integration

package tun

import (
	"os"
	"testing"
)

// TestLiveTUN is the opt-in that would open a utun device.
// Default tests, including CI, never reach that. The product path is
// Helper.Available / Platform, which refuses without CLASHGO_TUN_LIVE=1.
func TestLiveTUN(t *testing.T) {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("CI does not enable TUN")
	}
	if os.Getenv("CLASHGO_TUN_LIVE") != "1" {
		t.Skip("set CLASHGO_TUN_LIVE=1 to open a TUN device")
	}
	t.Skip("this build does not open a utun device")
}
