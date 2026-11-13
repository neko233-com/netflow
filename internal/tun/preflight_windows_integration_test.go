//go:build windows && integration

package tun

import (
	"os"
	"strings"
	"testing"
)

// This opt-in check only reads adapter state and never opens a TUN device.
func TestWindowsDetectsExistingTUN(t *testing.T) {
	if os.Getenv("NETFLOW_EXPECT_TUN_CONFLICT") != "1" {
		t.Skip("requires an already active TUN adapter")
	}
	if err := checkHost(); err == nil || !strings.Contains(err.Error(), "虚拟网卡") {
		t.Fatalf("expected active TUN conflict, got %v", err)
	}
}
