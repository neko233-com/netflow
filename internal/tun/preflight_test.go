package tun

import "testing"

func TestConflictingAdapters(t *testing.T) {
	for _, tc := range []struct {
		name, description string
		up, want          bool
	}{
		{"Mihomo", "Meta Tunnel", true, true},
		{"VPN", "Wintun Userspace Tunnel", true, true},
		{"Mihomo", "Meta Tunnel", false, false},
		{"Ethernet", "Intel Ethernet Controller", true, false},
	} {
		if got := conflictsWithTUN(tc.name, tc.description, tc.up); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}
