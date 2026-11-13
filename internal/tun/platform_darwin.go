//go:build darwin

package tun

import "os"

// hostPrivileged reports whether this process may open a utun device.
// Verge does that through a root helper. clash-go only treats an explicit
// live opt-in running as root as privileged, and never in CI (allowDevice).
func hostPrivileged() bool { return os.Geteuid() == 0 }
