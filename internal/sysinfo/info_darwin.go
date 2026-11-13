//go:build darwin

package sysinfo

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func Current() (string, string) {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil || version == "" {
		version, _ = unix.Sysctl("kern.osrelease")
	}
	if version == "" {
		return "macOS", runtime.GOARCH
	}
	return "macOS", version + " · " + runtime.GOARCH
}
