package app

import (
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/core"
)

// Network probes run outside the native event loop, with a small shared
// concurrency limit so "test all" does not create unbounded work.
func (a *App) probeSiteAsync(url string, done func(int, error)) {
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		ms, err := a.probeSite(url)
		a.runOnMain(func() {
			done(ms, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) testProxyAsync(group, name, url string, timeout time.Duration, done func(int, error)) {
	a.testProxyForProfileAsync(group, name, url, timeout, a.core.ProfileID(), done)
}

func (a *App) testProxyForProfileAsync(group, name, url string, timeout time.Duration, profileID string, done func(int, error)) {
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		var ms int
		var err error
		if a.core.ProfileID() != profileID {
			err = errors.New("active profile changed before the test began")
		} else {
			ms, err = a.core.TestDelay(group, name, url, timeout)
			if a.core.ProfileID() != profileID {
				ms, err = 0, errors.New("active profile changed during the test")
			}
		}
		a.runOnMain(func() {
			if a.core.ProfileID() != profileID {
				ms, err = 0, errors.New("active profile changed during the test")
			}
			done(ms, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) checkUnlockAsync(name string, done func(string, string, int, error)) {
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		status, region, ms, err := a.checkUnlock(name)
		a.runOnMain(func() {
			done(status, region, ms, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) updateProxyProviderAsync(name string, done func(error)) {
	if a.tunBusy {
		done(errors.New("虚拟网卡正在切换"))
		return
	}
	slots, stop := a.probeSlots, a.probeStop
	profileID := a.core.ProfileID()
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		err := a.updateProviderForProfile("proxy", name, profileID)
		a.runOnMain(func() {
			if err == nil && a.core.ProfileID() == profileID {
				a.loadGroups()
				a.refreshHome()
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) updateRuleProviderAsync(name string, done func(error)) {
	if a.tunBusy {
		done(errors.New("虚拟网卡正在切换"))
		return
	}
	slots, stop := a.probeSlots, a.probeStop
	profileID := a.core.ProfileID()
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		err := a.updateProviderForProfile("rule", name, profileID)
		a.runOnMain(func() {
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) updateProviderForProfile(kind, name, profileID string) error {
	if kind == "proxy" {
		if engine, ok := a.core.(interface{ UpdateProxyProviderForProfile(string, string) error }); ok {
			return engine.UpdateProxyProviderForProfile(name, profileID)
		}
		if a.core.ProfileID() != profileID {
			return core.ErrProviderProfileChanged
		}
		return a.core.UpdateProxyProvider(name)
	}
	if kind == "rule" {
		if engine, ok := a.core.(interface{ UpdateRuleProviderForProfile(string, string) error }); ok {
			return engine.UpdateRuleProviderForProfile(name, profileID)
		}
		if a.core.ProfileID() != profileID {
			return core.ErrProviderProfileChanged
		}
		return a.core.UpdateRuleProvider(name)
	}
	return errors.New("unknown provider kind")
}
