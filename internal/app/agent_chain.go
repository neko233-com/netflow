package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/validation"
)

type chainProposal struct {
	draft   chainDraft
	checked validation.Result
	expires time.Time
}

func (a *App) prepareAgentChain(in agent.ChainPreviewArgs) (chainDraft, error) {
	if len(in.Hops) < 2 || len(in.Hops) > 8 {
		return chainDraft{}, errors.New("chain requires two to eight hops")
	}
	nodes := make([]ui.ProxyNode, 0, len(in.Hops))
	for _, hop := range in.Hops {
		nodes = append(nodes, ui.ProxyNode{Name: hop.Name, Provider: hop.Provider, SourceGroup: hop.Group})
	}
	return a.prepareChain(in.Target, nodes)
}
func chainHops(nodes []ui.ProxyNode) []agent.ChainHop {
	result := make([]agent.ChainHop, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, agent.ChainHop{Name: node.Name, Provider: node.Provider, Group: node.SourceGroup})
	}
	return result
}
func (a *App) pruneExpiredChainProposals(now time.Time) {
	for id, p := range a.agentChainProposals {
		if !p.expires.After(now) {
			delete(a.agentChainProposals, id)
		}
	}
}

func (a *App) finishAgentChainPreview(d chainDraft, checked validation.Result) (agent.ChainPreview, error) {
	if err := a.checkChainDraft(d, checked); err != nil {
		return agent.ChainPreview{}, err
	}
	now := time.Now()
	a.pruneExpiredChainProposals(now)
	used := 0
	for _, p := range a.agentChainProposals {
		used += len(p.draft.original)
	}
	if len(a.agentChainProposals) >= 8 || used+len(d.original) > 32<<20 {
		return agent.ChainPreview{}, errors.New("too many pending chain previews")
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return agent.ChainPreview{}, err
	}
	id := hex.EncodeToString(token[:])
	expires := now.Add(2 * time.Minute)
	if a.agentChainProposals == nil {
		a.agentChainProposals = make(map[string]chainProposal)
	}
	d.composed = nil
	a.agentChainProposals[id] = chainProposal{draft: d, checked: checked, expires: expires}
	warnings := []string{"The target group is restricted to this chain until disconnected; rules targeting that group affect new connections.", "Existing connections are not rerouted. Chain state is cleared on process restart."}
	warnings = append(warnings, checked.Warnings...)
	return agent.ChainPreview{ProposalID: id, ProfileID: d.active.ProfileID, Target: d.active.Spec.Target, Hops: chainHops(d.active.Nodes), ExpiresAt: expires, Warnings: warnings}, nil
}
func (a *App) agentChainPreview(in agent.ChainPreviewArgs) (agent.ChainPreview, error) {
	d, err := a.prepareAgentChain(in)
	if err != nil {
		return agent.ChainPreview{}, err
	}
	checked, err := validateConfigurations(context.Background(), a.dir, []validation.Config{{ID: d.active.ProfileID, Body: d.composed}})
	if err != nil {
		return agent.ChainPreview{}, err
	}
	return a.finishAgentChainPreview(d, checked)
}
func (a *App) agentChainApply(id string) (agent.ChainStatus, error) {
	p, ok := a.agentChainProposals[id]
	delete(a.agentChainProposals, id)
	if !ok || !p.expires.After(time.Now()) {
		return agent.ChainStatus{}, errors.New("chain proposal missing or expired; preview again")
	}
	if err := a.finishChain(p.draft, p.checked); err != nil {
		return agent.ChainStatus{}, err
	}
	return a.agentChainStatus(), nil
}
func (a *App) agentChainStatus() agent.ChainStatus {
	if a == nil {
		return agent.ChainStatus{}
	}
	active := a.chain.Load()
	if active == nil {
		return agent.ChainStatus{}
	}
	status := agent.ChainStatus{Configured: true, ProfileID: active.ProfileID, Target: active.Spec.Target, Hops: chainHops(active.Nodes)}
	if err := a.checkChainRouting(active); err != nil {
		status.Warning = err.Error()
	} else {
		status.Active = true
	}
	return status
}
