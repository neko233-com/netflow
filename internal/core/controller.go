package core

import (
	"net"
	"strings"

	"github.com/metacubex/mihomo/hub/route"
)

// startExternalController listens only on a secret-protected loopback address.
func startExternalController(addr, secret string, debug bool) {
	if !safeController(addr, secret) {
		return
	}
	route.ReCreateServer(&route.Config{
		Addr:    addr,
		Secret:  secret,
		IsDebug: debug,
	})
}

// The app does not need the HTTP API itself. An imported subscription must
// not accidentally expose an unauthenticated controller to other programs.
func safeController(addr, secret string) bool {
	if strings.TrimSpace(secret) == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
