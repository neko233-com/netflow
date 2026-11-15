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
type guiProfileOperation struct {
	done       chan struct{}
	reloadDone chan struct{}
	cancelDone chan struct{}
	canceled   bool
	rollback   bool
	quit       bool
	finished   func(error)
}

// useProfileAsync is called on the GUI event loop. Schedule the actual start
// for a later event so the current view frame has finished using the model.
func (a *App) useProfileAsync(uid string, done func(error)) {
	if a.guiProfileBusy() {
		done(errors.New("配置正在应用，请稍后重试"))
		return
	}
	if a.tunBusy {
		done(errors.New("虚拟网卡正在切换，请稍后重试"))
		return
	}
	op := &guiProfileOperation{done: make(chan struct{}), finished: done}
	a.guiOperation = op
	if a.model != nil {
		a.model.OperationMessage = "正在切换订阅"
		a.model.OperationCancel = func() { a.cancelGUIProfileOperation(op) }
	}
	if a.win != nil {
		a.win.SetTitle("NetFlow - 正在切换订阅")
		a.win.Invalidate()
	}
	go a.runOnMain(func() {
		if op.canceled {
			a.finishGUIProfileOperation(op, context.Canceled)
			return
		}
		tx, err := a.beginProfileSwitch(uid)
		if err != nil {
			a.finishGUIProfileOperation(op, err)
			return
		}
		a.guiBarrier.Store(op)
		if a.core == nil || !a.core.Status().Running {
			a.finishGUIProfileReload(op, tx, nil)
			return
		}
		op.reloadDone = make(chan struct{})
		go func() {
			err := a.core.Reload()
			close(op.reloadDone)
			a.runOnMainUnrestricted(func() { a.finishGUIProfileReload(op, tx, err) })
		}()
	})
}

func (a *App) cancelGUIProfileOperation(op *guiProfileOperation) {
	if a.guiOperation != op {
		return
	}
	if op.rollback {
		// On an explicit quit, the restored on-disk configuration is already
		// safe. Interrupt a stalled rollback so shutdown can stop the kernel.
		if op.quit && op.cancelDone == nil {
			a.requestGUIProfileCancellation(op)
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
	a.requestGUIProfileCancellation(op)
}

func (a *App) requestGUIProfileCancellation(op *guiProfileOperation) {
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

func (a *App) finishGUIProfileReload(op *guiProfileOperation, tx *profileSwitch, reloadErr error) {
	// A late cancellation must finish before a rollback reload or a later
	// transaction begins; otherwise it could cancel the wrong application.
	if op.cancelDone != nil {
		done := op.cancelDone
		op.cancelDone = nil
		go func() {
			<-done
			a.runOnMainUnrestricted(func() { a.finishGUIProfileReload(op, tx, reloadErr) })
		}()
		return
	}
	if reloadErr == nil && op.canceled {
		reloadErr = context.Canceled
	}
	if reloadErr == nil {
		reloadErr = a.commitProfileSwitch(tx)
	}
	if reloadErr == nil {
		a.finishGUIProfileOperation(op, nil)
		return
	}
	op.rollback = true
	needReload, restoreErr := a.beginProfileSwitchRollback(tx)
	if op.quit && restoreErr != nil {
		log.Print("profile configuration rollback failed during quit; inspect the configuration before restarting")
	}
	if restoreErr != nil || !needReload || op.quit {
		a.finishGUIProfileOperation(op, profileSwitchError(reloadErr, restoreErr))
		return
	}
	op.reloadDone = make(chan struct{})
	go func() {
		err := a.core.Reload()
		close(op.reloadDone)
		a.runOnMainUnrestricted(func() {
			a.finishGUIProfileRollback(op, reloadErr, err)
		})
	}()
}

func (a *App) finishGUIProfileRollback(op *guiProfileOperation, cause, rollbackErr error) {
	if op.cancelDone != nil {
		done := op.cancelDone
		op.cancelDone = nil
		go func() {
			<-done
			a.runOnMainUnrestricted(func() { a.finishGUIProfileRollback(op, cause, rollbackErr) })
		}()
		return
	}
	a.finishGUIProfileOperation(op, profileSwitchError(cause, rollbackErr))
}

func (a *App) finishGUIProfileOperation(op *guiProfileOperation, err error) {
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
func (a *App) guiProfileBusy() bool {
	return a.guiOperation != nil || a.guiBarrier.Load() != nil
}
