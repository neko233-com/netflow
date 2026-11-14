package app

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/conn"
)

const maxAgentPageBytes = 256 << 10

func connectionPage(items []conn.Item, in agent.ConnectionsArgs) (agent.ConnectionsResult, error) {
	if in.Offset < 0 || in.Limit < 0 || in.Limit > 500 {
		return agent.ConnectionsResult{}, errors.New("offset must be nonnegative and limit must be at most 500")
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	items = append([]conn.Item(nil), items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if in.Offset > len(items) {
		in.Offset = len(items)
	}
	out := agent.ConnectionsResult{Total: len(items), Offset: in.Offset, NextOffset: in.Offset, Connections: []conn.Item{}}
	encodedBytes := 2
	for out.NextOffset < len(items) && len(out.Connections) < in.Limit {
		item := items[out.NextOffset]
		encoded, err := json.Marshal(item)
		if err != nil {
			return agent.ConnectionsResult{}, err
		}
		if len(encoded)+2 > maxAgentPageBytes {
			if len(out.Connections) > 0 {
				break
			}
			return agent.ConnectionsResult{}, errors.New("one connection exceeds the page size limit")
		}
		if encodedBytes+len(encoded)+1 > maxAgentPageBytes {
			break
		}
		encodedBytes += len(encoded) + 1
		out.Connections = append(out.Connections, item)
		out.NextOffset++
	}
	return out, nil
}

func (a *App) agentConnections(in agent.ConnectionsArgs) (agent.ConnectionsResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return agent.ConnectionsResult{}, errors.New("core is not running")
	}
	items, _, _ := a.core.Connections()
	return connectionPage(items, in)
}

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
	out := agent.RulesResult{Total: len(items), Offset: offset, NextOffset: offset, Rules: []agent.Rule{}}
	encodedBytes := 2
	for out.NextOffset < len(items) && len(out.Rules) < in.Limit {
		item := items[out.NextOffset]
		rule := agent.Rule{Type: item.Type, Payload: item.Payload, Policy: item.Proxy}
		encoded, err := json.Marshal(rule)
		if err != nil {
			return agent.RulesResult{}, err
		}
		if len(encoded)+2 > maxAgentPageBytes {
			if len(out.Rules) > 0 {
				break
			}
			return agent.RulesResult{}, errors.New("one rule exceeds the page size limit")
		}
		if encodedBytes+len(encoded)+1 > maxAgentPageBytes {
			break
		}
		encodedBytes += len(encoded) + 1
		out.Rules = append(out.Rules, rule)
		out.NextOffset++
	}
	return out, nil
}
