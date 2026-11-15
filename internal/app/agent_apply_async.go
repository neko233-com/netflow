package app

import "github.com/neko233-com/netflow/internal/agent"

// The preview is consumed and checked on the app event loop. Only the kernel
// reload runs in the background; rollback uses the same revision checks as
// the headless transaction.
func (a *App) agentApplyAsync(id string, done func(agent.ApplyResult, error)) {
	var result agent.ApplyResult
	a.startGUIConfigOperation("正在应用规则", func() (*guiConfigTransaction, error) {
		tx, err := a.beginAgentApply(id)
		if err != nil {
			return nil, err
		}
		return &guiConfigTransaction{
			reload: tx.active,
			commit: func() error {
				var err error
				result, err = a.finishAgentApply(tx)
				return err
			},
			rollback: func() (bool, error) { return a.rollbackAgentApply(tx) },
			wrap:     agentApplyError,
		}, nil
	}, func(err error) { done(result, err) })
}
