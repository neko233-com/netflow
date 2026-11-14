package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/tun"
)

func (a *App) tunRequestAvailable() bool { return a.tunAllowed() || canLaunchTUNWorker() }

// requestTUN keeps the window responsive during the Windows consent prompt.
// All application state and kernel handoff happens back on the UI thread.
func (a *App) requestTUN(on bool, done func(error)) {
	finish := func(err error) {
		if err != nil {
			a.tunLastError = err.Error()
		} else {
			a.tunLastError = ""
		}
		done(err)
		if err == nil && a.model != nil {
			if source, ok := a.core.(interface{ CacheWarning() string }); ok {
				if warning := source.CacheWarning(); warning != "" {
					a.model.Notice = "虚拟网卡已切换，但集合缓存未保存: " + warning
				}
			}
		}
	}
	if a.tunBusy {
		finish(errors.New("虚拟网卡正在切换"))
		return
	}
	if !on || a.tunAllowed() {
		finish(a.SetTUN(on))
		return
	}
	if !canLaunchTUNWorker() {
		finish(tun.ErrNeedService)
		return
	}
	if a.core == nil || !a.core.Status().Running || a.store == nil {
		finish(errors.New("内核未运行，无法开启虚拟网卡"))
		return
	}
	if err := a.checkTUNHost(); err != nil {
		finish(err)
		return
	}
	a.tunBusy = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		worker, err := launchTUNWorker(ctx)
		ran := false
		a.runOnMain(func() {
			ran = true
			defer func() { a.tunBusy = false }()
			if err == nil {
				err = a.enableWorkerTUN(worker)
			}
			finish(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
		if !ran && worker != nil {
			if c, ok := worker.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	}()
}

func (a *App) enableWorkerTUN(worker coreEngine) error {
	if worker == nil {
		return errors.New("特权内核不可用")
	}
	sw, ok := a.core.(*switchableEngine)
	if !ok || a.store == nil {
		if c, ok := worker.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		return errors.New("内核切换不可用")
	}
	if err := a.checkTUNHost(); err != nil {
		if c, ok := worker.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		return err
	}
	wasPrivileged := a.privilegedTUN
	// Start the worker with TUN still off. Restore saved node selections before
	// the reload which changes system routing, avoiding a default-node window.
	err := sw.replace(worker,
		func() error { a.privilegedTUN = true; return nil }, nil,
		func() error { a.privilegedTUN = wasPrivileged; return nil },
	)
	if err != nil {
		a.refreshHome()
		return err
	}
	if a.model != nil {
		a.loadGroups()
	}
	if err = a.setDirectTUN(true); err != nil {
		recoveryErr := a.releaseWorkerTUN()
		a.refreshHome()
		return errors.Join(err, recoveryErr)
	}
	a.refreshHome()
	return nil
}

func (a *App) releaseWorkerTUN() error {
	if !a.privilegedTUN {
		return nil
	}
	sw, ok := a.core.(*switchableEngine)
	if !ok {
		return errors.New("内核切换不可用")
	}
	var local coreEngine = core.New()
	if a.localCoreFactory != nil {
		local = a.localCoreFactory()
	}
	err := sw.replace(local,
		func() error { a.privilegedTUN = false; return nil }, nil,
		func() error { a.privilegedTUN = true; return nil },
	)
	if err == nil && a.model != nil {
		a.loadGroups()
	}
	a.refreshHome()
	if err != nil {
		return fmt.Errorf("切换普通内核失败: %w", err)
	}
	return nil
}

func (a *App) tunActionDone(err error) {
	if a.model != nil {
		if err != nil {
			a.model.Notice = err.Error()
		} else {
			a.model.Notice = "虚拟网卡模式已更新"
		}
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}
