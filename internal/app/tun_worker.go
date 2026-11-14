package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/tun"
)

func (a *App) tunRequestAvailable() bool { return a.tunAllowed() || canLaunchTUNWorker() }

// Auto-start is opt-in and GUI-only; it uses the same preflight and consent
// path as an explicit toggle. Headless serve retains its own --tun setting.
func (a *App) requestPreferredTUN(request func(bool, func(error))) {
	if a == nil || a.headless || a.model == nil || !a.model.Prefs.AutoStartTUN || a.settings.TUN || request == nil {
		return
	}
	request(true, a.tunActionDone)
}

func (a *App) setTUNAutoStart(on bool) error {
	if a == nil || a.model == nil || a.store == nil {
		return errors.New("启动选项不可用")
	}
	if a.tunBusy {
		return errors.New("虚拟网卡正在切换，请稍后重试")
	}
	next := a.model.Prefs
	next.AutoStartTUN = on
	next.TUN = a.settings.TUN
	next.SystemProxy = a.settings.SystemProxy
	if err := a.savePrefs(next); err != nil {
		return err
	}
	a.model.Prefs.AutoStartTUN = on
	return nil
}

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
	if on {
		if err := a.checkSettingsCurrent(); err != nil {
			finish(err)
			return
		}
	}
	if !on || a.tunAllowed() {
		err := a.SetTUN(on)
		if !on && errors.Is(err, coreipc.ErrKernelBusy) && a.privilegedTUN {
			if sw, ok := a.core.(*switchableEngine); ok {
				a.stopBusyWorkerTUN(sw, finish)
				return
			}
		}
		finish(err)
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

// stopBusyWorkerTUN cancels worker activity off the event loop, then transfers
// its stopped kernel state to a normal kernel without re-enabling TUN.
func (a *App) stopBusyWorkerTUN(sw *switchableEngine, finish func(error)) {
	snapshot := sw.handoffSnapshot()
	if !snapshot.status.Running || snapshot.status.ConfigDir == "" {
		finish(errors.New("内核未运行，无法关闭虚拟网卡"))
		return
	}
	a.tunBusy = true
	go func() {
		stopErr := sw.Stop()
		a.runOnMain(func() {
			if stopErr != nil && !errors.Is(stopErr, coreipc.ErrKernelStoppedBeforeFinalization) {
				a.tunBusy = false
				a.refreshHome()
				finish(fmt.Errorf("停止特权内核失败: %w", stopErr))
				return
			}
			a.settings.TUN = false
			saveErr := a.store.Save(a.settings)
			a.refreshHome()
			deadline := time.Now().Add(5 * time.Second)
			var attempt func()
			attempt = func() {
				var local coreEngine = core.New()
				if a.localCoreFactory != nil {
					local = a.localCoreFactory()
				}
				err := sw.replaceStopped(local,
					func() error { a.privilegedTUN = false; return nil }, nil,
					func() error { a.privilegedTUN = true; return nil }, snapshot)
				if errors.Is(err, errHandoffBusy) && time.Now().Before(deadline) {
					time.AfterFunc(25*time.Millisecond, func() { a.runOnMain(attempt) })
					return
				}
				if err != nil && !sw.Status().Running {
					if restartErr := sw.Start(snapshot.status.ConfigDir); restartErr != nil {
						err = errors.Join(err, fmt.Errorf("恢复关闭 TUN 的原内核失败: %w", restartErr))
					}
				}
				if err == nil && a.model != nil {
					a.loadGroups()
				}
				a.tunBusy = false
				a.refreshHome()
				var warnings []error
				if stopErr != nil {
					warnings = append(warnings, stopErr)
				}
				if saveErr != nil {
					warnings = append(warnings, fmt.Errorf("设置保存失败: %w", saveErr))
				}
				if err != nil {
					warnings = append(warnings, fmt.Errorf("切换普通内核失败: %w", err))
				}
				if len(warnings) != 0 {
					finish(fmt.Errorf("虚拟网卡已关闭，但%w", errors.Join(warnings...)))
					return
				}
				finish(nil)
			}
			attempt()
		})
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
