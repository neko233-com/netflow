package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/rewrite"
)

func (a *App) agentRollbackPreview(in agent.RollbackArgs) (agent.Preview, error) {
	draft, err := a.prepareAgentRollback(in)
	if err != nil {
		return agent.Preview{}, err
	}
	checked, err := validateConfigurations(context.Background(), a.dir, draft.configs)
	if err != nil {
		return agent.Preview{}, err
	}
	if err := a.verifyDraftSources(draft, checked); err != nil {
		return agent.Preview{}, err
	}
	return a.finishAgentPreview(draft, checked)
}

func (a *App) agentRewriteHistory() (agent.RewriteHistory, error) {
	if a.rewrites == nil {
		return agent.RewriteHistory{}, errors.New("rewrite store is unavailable")
	}
	if err := a.rewrites.CheckCurrent(); err != nil {
		return agent.RewriteHistory{}, err
	}
	return agent.RewriteHistory{Entries: a.rewrites.History()}, nil
}

// prepareAgentRollback produces an ordinary preview draft, retaining the
// existing validation, stale-source checks, apply and rollback guarantees.
func (a *App) prepareAgentRollback(in agent.RollbackArgs) (previewDraft, error) {
	if a.rewrites == nil || a.core == nil || in.Revision == nil {
		return previewDraft{}, errors.New("historical revision is required")
	}
	if err := a.rewrites.CheckCurrent(); err != nil {
		return previewDraft{}, err
	}
	previous, err := a.rewrites.Historical(*in.Revision)
	if err != nil {
		return previewDraft{}, err
	}
	change := agent.Change{Scope: in.Scope, Operation: "set"}
	var originalExpiry time.Time
	switch in.Scope {
	case "global":
		if in.ProfileID != "" || in.ConnectionID != "" || in.CloseExisting {
			return previewDraft{}, errors.New("unexpected rollback arguments for global scope")
		}
		change.Layer = previous.Global
	case "profile":
		if in.ProfileID == "" || in.ConnectionID != "" || in.CloseExisting {
			return previewDraft{}, errors.New("profile id is required for profile rollback")
		}
		change.ProfileID = in.ProfileID
		if layer, ok := previous.Profiles[in.ProfileID]; ok {
			change.Layer = layer
		} else {
			change.Operation = "clear"
		}
	case "connection":
		if in.ConnectionID == "" || in.ProfileID != "" {
			return previewDraft{}, errors.New("connection id is required for connection rollback")
		}
		change.ConnectionID, change.CloseExisting = in.ConnectionID, in.CloseExisting
		var old *rewrite.Connection
		for i := range previous.Connections {
			if previous.Connections[i].ID == in.ConnectionID {
				old = &previous.Connections[i]
				break
			}
		}
		if old == nil {
			if in.CloseExisting {
				return previewDraft{}, errors.New("cannot close a connection when clearing its matcher")
			}
			change.Operation = "clear"
			break
		}
		if old.ProfileID != a.core.ProfileID() {
			return previewDraft{}, errors.New("historical matcher belongs to another active profile")
		}
		remaining := int(time.Until(old.ExpiresAt).Seconds())
		if remaining < 1 {
			return previewDraft{}, errors.New("historical connection matcher has expired")
		}
		if remaining > 86400 {
			remaining = 86400
		}
		separator := strings.LastIndex(old.Rule, ",")
		if separator < 0 {
			return previewDraft{}, errors.New("historical connection matcher is invalid")
		}
		change.Policy, change.TTLSeconds = old.Rule[separator+1:], remaining
		matched := false
		items, _, _ := a.core.Connections()
		for _, item := range items {
			if item.ID != in.ConnectionID {
				continue
			}
			rule, ruleErr := connectionRule(item, change.Policy)
			if ruleErr == nil && rule == old.Rule {
				matched = true
			}
		}
		if !matched {
			return previewDraft{}, errors.New("historical connection changed or closed")
		}
		originalExpiry = old.ExpiresAt
	default:
		return previewDraft{}, errors.New("scope must be global, profile, or connection")
	}
	draft, err := a.prepareAgentPreview(change)
	if err != nil {
		return previewDraft{}, err
	}
	if !originalExpiry.IsZero() {
		for i := range draft.state.Connections {
			if draft.state.Connections[i].ID == in.ConnectionID && draft.state.Connections[i].ExpiresAt.After(originalExpiry) {
				draft.state.Connections[i].ExpiresAt = originalExpiry
			}
		}
	}
	draft.warnings = append(draft.warnings, "This revision is a stored state snapshot; a previous kernel reload may have failed. Only the selected scope is restored.")
	return draft, nil
}
