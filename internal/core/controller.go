//go:build !race

package core

import (
	"net"
	"strings"

	"github.com/metacubex/mihomo/hub/route"
)

// externalControllerEnabled is false in the race-detector build, where
// startExternalController is a no-op. See controller_race.go.
const externalControllerEnabled = true

// startExternalController listens on the profile's external-controller
// after hub.Parse has set the log level. mihomo starts that server on a
// goroutine with no happens-before edge to Shutdown, so the race detector
// build leaves it down; see controller_race.go.
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
