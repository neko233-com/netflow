package app

import (
	"context"
	"errors"
	"time"
)

// A restart can wait on uncached providers just like a reload. Stop and start
// on the worker while serializing all other mutations behind the GUI barrier.
func (a *App) restartCoreAsync(done func(error)) {
	previous := a.guiOperation
	a.startGUIConfigOperation("正在重启内核", func() (*guiConfigTransaction, error) {
		if a.core == nil || a.dir == "" {
			return nil, errors.New("内核不可用")
		}
		engine, dir, worker := a.core, a.dir, a.privilegedTUN
		return &guiConfigTransaction{
			reload: true,
			apply: func(ctx context.Context) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := engine.Stop(); err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if !worker {
					if starter, ok := engine.(interface {
						StartContext(context.Context, string) error
					}); ok {
						return starter.StartContext(ctx, dir)
					}
				}
				return engine.Start(dir)
			},
			commit: func() error {
				a.started = time.Now()
				a.loadGroups()
				a.refreshHome()
				return nil
			},
			rollback: func() (bool, error) { return false, nil },
			wrap: func(_ error, _ error) error {
				a.refreshHome()
				status := engine.Status()
				if status.Error != "" {
					return errors.New("重启未完成，无法确认内核运行状态；请检查后重试")
				}
				if status.Running {
					return errors.New("重启未完成，请检查内核运行状态")
				}
				return errors.New("内核已停止，重启未完成；重试可能重新启用虚拟网卡")
			},
		}, nil
	}, done)
	if a.guiOperation != nil && a.guiOperation != previous {
		a.guiOperation.cancelMessage = "正在取消重启"
		if a.model != nil {
			a.model.OperationDetail = "取消后内核可能保持停止；重试可能重新启用虚拟网卡。"
			a.model.OperationCancelLabel = "取消重启"
		}
		if a.win != nil {
			a.win.Invalidate()
		}
	}
}
