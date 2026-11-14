package app

import (
	"context"
	"errors"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/rewrite"
)

func (a *App) loadRewrite(scope, profileID string) (rewrite.Layer, error) {
	if a.rewrites == nil {
		return rewrite.Layer{}, errors.New("规则覆写尚未就绪")
	}
	if err := a.rewrites.CheckCurrent(); err != nil {
		return rewrite.Layer{}, err
	}
	state := a.rewrites.Snapshot()
	switch scope {
	case "global":
		return state.Global, nil
	case "profile":
		if profileID == "" {
			return rewrite.Layer{}, errors.New("请先选择订阅")
		}
		return state.Profiles[profileID], nil
	default:
		return rewrite.Layer{}, errors.New("未知规则范围")
	}
}

// Preparation and final acceptance run on the UI thread; potentially slow
// external validation runs in the background just as it does for Agent calls.
func (a *App) previewDraftAsync(draft previewDraft, err error, done func(agent.Preview, error)) func() {
	if err != nil {
		done(agent.Preview{}, err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		checked, err := validateConfigurations(ctx, a.dir, draft.configs)
		if err == nil {
			err = a.verifyDraftSources(draft, checked)
		}
		a.runOnMain(func() {
			var result agent.Preview
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				result, err = a.finishAgentPreview(draft, checked)
			}
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
	return cancel
}

func (a *App) previewRewriteAsync(change agent.Change, done func(agent.Preview, error)) func() {
	draft, err := a.prepareAgentPreview(change)
	return a.previewDraftAsync(draft, err, done)
}

func (a *App) previewRollbackAsync(args agent.RollbackArgs, done func(agent.Preview, error)) func() {
	draft, err := a.prepareAgentRollback(args)
	return a.previewDraftAsync(draft, err, done)
}
