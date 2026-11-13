//go:build !darwin

package tun

func hostPrivileged() bool { return false }
