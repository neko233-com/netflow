package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		if method == "show" {
			a.showMain()
			value = map[string]bool{"shown": true}
			return
		}
		value, callErr = a.agentCommand(method, args)
	})
	if !executed {
		return nil, errors.New("desktop application is shutting down")
	}
	return value, callErr
}

func (a *App) agentCommand(method string, args json.RawMessage) (value any, callErr error) {
	switch method {
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
	case "groups":
		value, callErr = a.agentGroups()
	case "rules":
		var input agent.RulesArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentRules(input)
		}
	case "select":
		var input agent.SelectArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentSelect(input)
		}
	case "tun":
		var input agent.TunArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.Enabled == nil {
				callErr = errors.New("enabled is required")
			} else {
				var completed, returned bool
				var immediateErr error
				a.requestTUN(*input.Enabled, func(err error) {
					a.tunActionDone(err)
					if !returned {
						completed, immediateErr = true, err
					}
				})
				returned = true
				callErr = immediateErr
				if !completed || callErr == nil {
					value = agent.TunResult{Accepted: true, Pending: !completed, TUN: a.core.Status().TUN}
				}
			}
		}
	case "mode":
		var input agent.ModeArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				callErr = a.SetMode(input.Mode)
			}
			value = agent.ActionResult{OK: callErr == nil}
		}
	case "use-profile":
		var input agent.ProfileArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				callErr = a.UseProfile(input.ProfileID)
			}
			value = agent.ActionResult{OK: callErr == nil}
		}
	case "close-connection":
		var input agent.ConnectionArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.ConnectionID == "" {
				callErr = errors.New("connection id is required")
			} else if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				var closed bool
				closed, callErr = a.core.CloseExistingConnection(input.ConnectionID)
				value = agent.CloseResult{Closed: closed}
			}
		}
	default:
		callErr = errors.New("unknown agent method")
	}
	return value, callErr
}

func decodeStrict(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
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
