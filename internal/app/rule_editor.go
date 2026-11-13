package app

import (
	"errors"

	"github.com/neko233-com/netflow/internal/rewrite"
)

func (a *App) loadRewrite(scope, profileID string) (rewrite.Layer, error) {
	if a.rewrites == nil {
		return rewrite.Layer{}, errors.New("规则覆写尚未就绪")
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
