package app

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

type profileSwitch struct {
	uid, rel, previousProfile   string
	body, oldConfig, nextConfig []byte
	hadOld                      bool
	catalog                     profile.File
	snapshot                    []byte
}

// All fields other than done are owned by the app event loop. done is closed
// only after the kernel operation and any cancellation request have ended.
type guiConfigOperation struct {
	done       chan struct{}
	reloadDone chan struct{}
	cancelDone chan struct{}
	canceled   bool
	rollback   bool
	quit       bool
	finished   func(error)
}

// The callbacks run on the app event loop. The only work moved off that loop
// is the kernel reload, including the reload required to restore old state.
type guiConfigTransaction struct {
	commit   func() error
	rollback func() (bool, error)
	wrap     func(error, error) error
	reload   bool
}

func (a *App) useProfileAsync(uid string, done func(error)) {
	a.startGUIConfigOperation("正在切换订阅", func() (*guiConfigTransaction, error) {
		tx, err := a.beginProfileSwitch(uid)
		if err != nil {
			return nil, err
		}
		return &guiConfigTransaction{
			commit:   func() error { return a.commitProfileSwitch(tx) },
			rollback: func() (bool, error) { return a.beginProfileSwitchRollback(tx) },
			wrap:     profileSwitchError,
			reload:   a.core != nil && a.core.Status().Running,
		}, nil
	}, done)
}

// startGUIConfigOperation is called on the GUI event loop. Schedule the start
// for a later event so the current view frame has finished using the model.
func (a *App) startGUIConfigOperation(message string, begin func() (*guiConfigTransaction, error), done func(error)) {
	if a.guiConfigBusy() {
		done(errors.New("配置正在应用，请稍后重试"))
		return
	}
	if a.tunBusy {
		done(errors.New("虚拟网卡正在切换，请稍后重试"))
		return
	}
	op := &guiConfigOperation{done: make(chan struct{}), finished: done}
	a.guiOperation = op
	if a.model != nil {
		a.model.OperationMessage = message
		a.model.OperationCancel = func() { a.cancelGUIConfigOperation(op) }
	}
	if a.win != nil {
		a.win.SetTitle("NetFlow - " + message)
		a.win.Invalidate()
	}
	go a.runOnMain(func() {
		if op.canceled {
			a.finishGUIConfigOperation(op, context.Canceled)
			return
		}
		tx, err := begin()
		if err != nil {
			a.finishGUIConfigOperation(op, err)
			return
		}
		a.guiBarrier.Store(op)
		if !tx.reload {
			a.finishGUIConfigReload(op, tx, nil)
			return
		}
		op.reloadDone = make(chan struct{})
		go func() {
			err := a.core.Reload()
			close(op.reloadDone)
			a.runOnMainUnrestricted(func() { a.finishGUIConfigReload(op, tx, err) })
		}()
	})
}

func (a *App) cancelGUIConfigOperation(op *guiConfigOperation) {
	if a.guiOperation != op {
		return
	}
	if op.rollback {
		// On an explicit quit, the restored on-disk configuration is already
		// safe. Interrupt a stalled rollback so shutdown can stop the kernel.
		if op.quit && op.cancelDone == nil {
			a.requestGUIConfigCancellation(op)
		}
		return
	}
	if op.canceled {
		return
	}
	op.canceled = true
	if a.model != nil {
		a.model.OperationMessage = "正在取消并恢复配置"
		a.model.OperationCancel = nil
	}
	if a.win != nil {
		a.win.Invalidate()
	}
	if a.guiBarrier.Load() != op {
		return
	}
	a.requestGUIConfigCancellation(op)
}

func (a *App) requestGUIConfigCancellation(op *guiConfigOperation) {
	op.cancelDone = make(chan struct{})
	go func(done, reloadDone chan struct{}) {
		defer close(done)
		engine, ok := a.core.(interface {
			CancelActiveApply(context.Context) (bool, error)
		})
		if !ok {
			return
		}
		for {
			select {
			case <-reloadDone:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			accepted, _ := engine.CancelActiveApply(ctx)
			cancel()
			if accepted {
				return
			}
			select {
			case <-reloadDone:
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}(op.cancelDone, op.reloadDone)
}

func (a *App) finishGUIConfigReload(op *guiConfigOperation, tx *guiConfigTransaction, reloadErr error) {
	// A late cancellation must finish before a rollback reload or a later
	// transaction begins; otherwise it could cancel the wrong application.
	if op.cancelDone != nil {
		done := op.cancelDone
		op.cancelDone = nil
		go func() {
			<-done
			a.runOnMainUnrestricted(func() { a.finishGUIConfigReload(op, tx, reloadErr) })
		}()
		return
	}
	if reloadErr == nil && op.canceled {
		reloadErr = context.Canceled
	}
	if reloadErr == nil {
		reloadErr = tx.commit()
	}
	if reloadErr == nil {
		a.finishGUIConfigOperation(op, nil)
		return
	}
	op.rollback = true
	needReload, restoreErr := tx.rollback()
	if op.quit && restoreErr != nil {
		log.Print("configuration rollback failed during quit; inspect the configuration before restarting")
	}
	if restoreErr != nil || !needReload || op.quit {
		a.finishGUIConfigOperation(op, tx.wrap(reloadErr, restoreErr))
		return
	}
	op.reloadDone = make(chan struct{})
	go func() {
		err := a.core.Reload()
		close(op.reloadDone)
		a.runOnMainUnrestricted(func() {
			a.finishGUIConfigRollback(op, tx, reloadErr, err)
		})
	}()
}

func (a *App) finishGUIConfigRollback(op *guiConfigOperation, tx *guiConfigTransaction, cause, rollbackErr error) {
	if op.cancelDone != nil {
		done := op.cancelDone
		op.cancelDone = nil
		go func() {
			<-done
			a.runOnMainUnrestricted(func() { a.finishGUIConfigRollback(op, tx, cause, rollbackErr) })
		}()
		return
	}
	a.finishGUIConfigOperation(op, tx.wrap(cause, rollbackErr))
}

func (a *App) finishGUIConfigOperation(op *guiConfigOperation, err error) {
	if a.guiOperation != op {
		return
	}
	a.guiOperation = nil
	if op.finished != nil {
		op.finished(err)
	}
	if op.quit {
		// Keep queued mutations behind the barrier until the event loop has
		// actually stopped. The kernel may be only partly restored while the
		// quit sequence is about to stop it.
		a.guiBarrier.Store(op)
		if a.model != nil {
			a.model.OperationMessage = "正在退出"
			a.model.OperationCancel = nil
		}
		a.quitAfterGUIOperation()
		return
	}
	if a.model != nil {
		a.model.OperationMessage = ""
		a.model.OperationCancel = nil
	}
	a.guiBarrier.CompareAndSwap(op, nil)
	close(op.done)
	if a.win != nil {
		a.win.SetTitle("NetFlow")
		a.win.Invalidate()
	}
}

func (a *App) releaseGUIBarrierAfterExit() {
	if op := a.guiBarrier.Swap(nil); op != nil {
		close(op.done)
	}
}

// Called only on the GUI event loop.
func (a *App) guiConfigBusy() bool {
	return a.guiOperation != nil || a.guiBarrier.Load() != nil
}
