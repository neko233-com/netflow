package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
)

// runOnMain serializes mutations on the UI event loop in desktop mode and on
// a dedicated event loop in headless mode. It may decline work during shutdown.
func (a *App) runOnMain(fn func()) {
	if a.dispatch != nil {
		a.dispatch(fn)
		return
	}
	mygo.RunOnMain(fn)
}

type serialCall struct {
	fn   func()
	done chan struct{}
}

type serialDispatcher struct {
	calls chan serialCall
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newSerialDispatcher() *serialDispatcher {
	d := &serialDispatcher{calls: make(chan serialCall), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(d.done)
		for {
			select {
			case <-d.stop:
				return
			case call := <-d.calls:
				call.fn()
				close(call.done)
			}
		}
	}()
	return d
}

func (d *serialDispatcher) call(fn func()) {
	call := serialCall{fn: fn, done: make(chan struct{})}
	select {
	case <-d.stop:
		return
	case d.calls <- call:
		// Once accepted, wait for the callback even if shutdown starts, so
		// its caller can safely inspect callback results.
		<-call.done
	}
}

func (d *serialDispatcher) close() {
	d.once.Do(func() { close(d.stop) })
	<-d.done
}

// HeadlessOptions controls the foreground service. Ready runs only once the
// bridge is available and any explicitly requested TUN activation succeeded.
type HeadlessOptions struct {
	EnableTUN    bool
	Ready        func(tun bool)
	AllowStopped bool
	ReadyStatus  func(core.Status)
}

// RunHeadless uses the same configuration, kernel and Agent API as the GUI,
// without creating a native window or starting the MyGo UI event loop.
func (a *App) RunHeadless(ctx context.Context, opt HeadlessOptions) (resultErr error) {
	if ctx == nil {
		return errors.New("headless context is required")
	}
	if opt.AllowStopped && opt.EnableTUN {
		return errors.New("recovery mode cannot enable TUN")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.headlessCancel = cancel
	dir, err := a.dirs.ConfigDir()
	if err != nil {
		return err
	}
	lock, err := appdir.Acquire(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	a.headless = true
	a.headlessRecovery = opt.AllowStopped
	if err := a.Prepare(); err != nil {
		_ = a.core.Stop()
		return err
	}
	if a.core == nil || (!a.core.Status().Running && !opt.AllowStopped) {
		if a.core != nil {
			_ = a.core.Stop()
		}
		if a.model != nil && a.model.Home.Error != "" {
			return fmt.Errorf("core startup failed: %s", a.model.Home.Error)
		}
		return errors.New("core startup failed")
	}
	dispatcher := newSerialDispatcher()
	a.dispatch = dispatcher.call
	a.probeSlots = make(chan struct{}, 4)
	a.probeStop = make(chan struct{})
	if !opt.AllowStopped {
		a.startProfileAuto()
	}
	defer func() {
		// Prevent new callbacks, then wait for an active mutation to finish
		// before closing services and the kernel that owns TUN and routes.
		dispatcher.close()
		a.stopBackup()
		if a.profileAutoStop != nil {
			close(a.profileAutoStop)
		}
		if a.probeStop != nil {
			close(a.probeStop)
		}
		a.stopAgent()
		if err := a.core.Stop(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("stop core: %w", err))
		}
	}()
	if err := a.startAgent(); err != nil {
		return fmt.Errorf("start Agent bridge: %w", err)
	}
	if opt.EnableTUN {
		if !a.core.Status().Running {
			return errors.New("cannot enable TUN while the core is stopped")
		}
		finished := make(chan error, 1)
		a.runOnMain(func() { a.requestTUN(true, func(err error) { finished <- err }) })
		select {
		case err := <-finished:
			if err != nil {
				return fmt.Errorf("enable TUN: %w", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
	if opt.Ready != nil {
		opt.Ready(a.core.Status().TUN)
	}
	if opt.ReadyStatus != nil {
		opt.ReadyStatus(a.core.Status())
	}
	<-ctx.Done()
	return nil
}
