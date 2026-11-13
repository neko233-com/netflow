package app

import (
	"errors"
	"strings"

	"github.com/neko233-com/netflow/internal/agent"
)

func (a *App) agentGroups() (agent.GroupsResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running || a.model == nil {
		return agent.GroupsResult{}, errors.New("core is not running")
	}
	if err := a.loadGroupsWithSelection(false); err != nil {
		return agent.GroupsResult{}, err
	}
	result := agent.GroupsResult{Groups: []agent.ProxyGroup{}}
	for _, row := range a.model.Groups {
		g, err := a.core.Group(row.Name)
		if err != nil {
			continue
		}
		out := agent.ProxyGroup{Name: g.Name, Type: g.Type, Current: g.Now, Nodes: []agent.ProxyNode{}}
		for _, node := range g.Nodes {
			out.Nodes = append(out.Nodes, agent.ProxyNode{Name: node.Name, Type: node.Type, UDP: node.UDP})
		}
		result.Groups = append(result.Groups, out)
	}
	return result, nil
}

func (a *App) agentSelect(in agent.SelectArgs) (agent.ActionResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return agent.ActionResult{}, errors.New("core is not running")
	}
	if strings.TrimSpace(in.Group) == "" || strings.TrimSpace(in.Node) == "" {
		return agent.ActionResult{}, errors.New("group and node are required")
	}
	if err := a.core.Select(in.Group, in.Node); err != nil {
		return agent.ActionResult{}, err
	}
	actual := in.Node
	if value, err := a.core.Selected(in.Group); err == nil && value != "" {
		actual = value
	}
	a.applyProxySelection(in.Group, actual)
	result := agent.ActionResult{OK: true}
	if err := a.persistSelection(in.Group, in.Node); err != nil {
		result.Warnings = append(result.Warnings, "选择已生效，但保存失败: "+err.Error())
	}
	return result, nil
}

func (a *App) agentRules(in agent.RulesArgs) (agent.RulesResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return agent.RulesResult{}, errors.New("core is not running")
	}
	if in.Offset < 0 || in.Limit < 0 || in.Limit > 500 {
		return agent.RulesResult{}, errors.New("offset must be nonnegative and limit must be at most 500")
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	items := a.core.Rules()
	offset := in.Offset
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + in.Limit
	if end > len(items) {
		end = len(items)
	}
	out := agent.RulesResult{Total: len(items), Offset: offset, Rules: []agent.Rule{}}
	for _, item := range items[offset:end] {
		out.Rules = append(out.Rules, agent.Rule{Type: item.Type, Payload: item.Payload, Policy: item.Proxy})
	}
	return out, nil
}
