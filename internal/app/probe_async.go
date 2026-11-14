package app

import (
	"errors"
	"time"

	"github.com/egoist/mygo"
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
		mygo.RunOnMain(func() {
			done(ms, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) testProxyAsync(group, name, url string, done func(int, error)) {
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		ms, err := a.core.TestDelay(group, name, url, 10*time.Second)
		mygo.RunOnMain(func() {
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
		mygo.RunOnMain(func() {
			done(status, region, ms, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) updateProxyProviderAsync(name string, done func(error)) {
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
		mygo.RunOnMain(func() {
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
		mygo.RunOnMain(func() {
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
