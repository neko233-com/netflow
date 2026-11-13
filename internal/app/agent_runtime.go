package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/agent"
)

func (a *App) startAgent() error {
	bridge, err := agent.Start(a.dir, a.dispatchAgent)
	if err != nil {
		return err
	}
	a.agentBridge = bridge
	a.agentExpiryStop = make(chan struct{})
	go a.expiryLoop(a.agentExpiryStop)
	return nil
}

func (a *App) stopAgent() {
	if a.agentExpiryStop != nil {
		close(a.agentExpiryStop)
		a.agentExpiryStop = nil
	}
	if a.agentBridge != nil {
		_ = a.agentBridge.Close()
		a.agentBridge = nil
	}
}

func (a *App) dispatchAgent(ctx context.Context, method string, args json.RawMessage) (any, error) {
	var value any
	var callErr error
	executed := false
	mygo.RunOnMain(func() {
		executed = true
		if err := ctx.Err(); err != nil {
			callErr = err
			return
		}
		switch method {
		case "show":
			a.showMain()
			value = map[string]bool{"shown": true}
		case "status":
			value, callErr = a.agentStatus()
		case "preview":
			var change agent.Change
			if callErr = decodeStrict(args, &change); callErr == nil {
				value, callErr = a.agentPreview(change)
			}
		case "apply":
			var input agent.ApplyArgs
			if callErr = decodeStrict(args, &input); callErr == nil {
				value, callErr = a.agentApply(input.ProposalID)
			}
		default:
			callErr = errors.New("unknown agent method")
		}
	})
	if !executed {
		return nil, errors.New("desktop application is shutting down")
	}
	return value, callErr
}

func decodeStrict(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func (a *App) expiryLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			state := a.rewrites.Snapshot()
			expired := false
			for _, c := range state.Connections {
				if !c.ExpiresAt.After(now) {
					expired = true
					break
				}
			}
			if !expired {
				continue
			}
			mygo.RunOnMain(func() {
				if err := a.expireRules(time.Now()); err != nil && a.model != nil {
					a.model.Notice = "Agent 临时规则清理失败: " + err.Error()
					if a.win != nil {
						a.win.Invalidate()
					}
				}
			})
		}
	}
}

func (a *App) expireRules(now time.Time) error {
	old := a.rewrites.Snapshot()
	next := old
	next.Connections = nil
	for _, c := range old.Connections {
		if c.ExpiresAt.After(now) {
			next.Connections = append(next.Connections, c)
		}
	}
	if len(next.Connections) == len(old.Connections) {
		return nil
	}
	saved, err := a.rewrites.Replace(next, old.Revision)
	if err != nil {
		return err
	}
	if a.core != nil && a.core.Status().Running {
		if err = a.core.Reload(); err != nil {
			_, restoreErr := a.rewrites.Replace(old, saved.Revision)
			if restoreErr == nil {
				restoreErr = a.core.Reload()
			}
			if restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous rules: %w", restoreErr))
			}
			return err
		}
	}
	return nil
}
