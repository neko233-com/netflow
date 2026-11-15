package app

import (
	"errors"
	"fmt"

	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
)

func (a *App) setModeAsync(mode string, done func(error)) {
	a.startGUIConfigOperation("正在切换模式", func() (*guiConfigTransaction, error) {
		if a.tunBusy {
			return nil, errors.New("虚拟网卡正在切换，请稍后重试")
		}
		if a.chain.Load() != nil && a.core != nil && a.core.Status().Mode != mode {
			return nil, errors.New("请先断开链式代理，再切换模式")
		}
		if mode != "rule" && mode != "global" && mode != "direct" {
			return nil, errors.New("无效的代理模式")
		}
		if a.kernelOptions != nil {
			next := a.kernelOptions.Snapshot()
			next.Mode = &mode
			var old kernelopts.Options
			if err := a.stageKernelOptions(next, &old); err != nil {
				return nil, err
			}
			return &guiConfigTransaction{
				reload: true,
				commit: func() error {
					a.refreshHome()
					a.loadGroups()
					a.refreshHome()
					return nil
				},
				rollback: func() (bool, error) {
					err := a.kernelOptions.Replace(old)
					return err == nil, err
				},
				wrap: func(cause, restoreErr error) error {
					if restoreErr != nil {
						return errors.Join(cause, fmt.Errorf("恢复原设置失败: %w", restoreErr))
					}
					return cause
				},
			}, nil
		}
		if a.dir == "" {
			return &guiConfigTransaction{commit: func() error { return nil }, rollback: func() (bool, error) { return false, nil }, wrap: func(err, _ error) error { return err }}, nil
		}
		old, err := safepath.ReadFile(a.dir, "config.yaml")
		if err != nil {
			return nil, err
		}
		next := profile.SetMode(old, mode)
		if err := safepath.CompareAndWrite(a.dir, "config.yaml", old, next); err != nil {
			return nil, err
		}
		running := a.core != nil && a.core.Status().Running
		return &guiConfigTransaction{
			reload: running,
			commit: func() error {
				if a.model != nil {
					a.model.Home.Mode = mode
				}
				return nil
			},
			rollback: func() (bool, error) {
				err := safepath.CompareAndWrite(a.dir, "config.yaml", next, old)
				return err == nil && running, err
			},
			wrap: func(cause, restoreErr error) error {
				if restoreErr != nil {
					return errors.Join(cause, fmt.Errorf("恢复原代理模式失败: %w", restoreErr))
				}
				return cause
			},
		}, nil
	}, done)
}
