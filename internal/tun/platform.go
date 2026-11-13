package tun

import "os"

// Helper is the privileged side Verge calls a service helper.
// Available is false when the process must not open a TUN device.
type Helper interface {
	Available() bool
}

// Fake is a test helper. OK reports whether a device open would be allowed.
type Fake struct{ OK bool }

// Available reports OK.
func (f Fake) Available() bool { return f.OK }

// Platform is the controller App uses when the caller does not inject one.
// CI and machines without a helper refuse to enable TUN. The memory switch
// still records an allowed enable, but CI never allows it, and this package
// does not open a utun device itself.
func Platform() Controller {
	return &gated{inner: NewMemory(), allow: allowDevice()}
}

type gated struct {
	inner *Memory
	allow bool
}

func (g *gated) Available() bool { return g != nil && g.allow }

func (g *gated) Current() (bool, error) {
	if g == nil || g.inner == nil {
		return false, nil
	}
	return g.inner.Current()
}

func (g *gated) Set(enabled bool) error {
	if enabled && !g.Available() {
		return ErrNeedService
	}
	return g.inner.Set(enabled)
}

func allowDevice() bool {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		return false
	}
	if os.Getenv("CLASHGO_TUN_LIVE") != "1" {
		return false
	}
	return hostPrivileged()
}
