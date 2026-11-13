//go:build !windows && !darwin

package sysinfo

import "runtime"

func Current() (string, string) { return runtime.GOOS, runtime.GOARCH }
