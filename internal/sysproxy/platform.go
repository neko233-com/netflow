package sysproxy

import "runtime"

// Platform is the controller the app uses when the caller does not pass one.
// macOS gets the networksetup/scutil implementation. Other systems get the
// in-memory fake so tests and non-macOS builds do not touch an OS proxy.
func Platform() Controller {
	if runtime.GOOS == "darwin" {
		return NewSystem()
	}
	return platformOther()
}
