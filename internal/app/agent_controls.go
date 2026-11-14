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

func boundedAgentPage[T any](items []T, offset, limit, maxBytes int) ([]T, int, int, error) {
	if offset < 0 || limit < 0 || limit > 500 {
		return nil, 0, 0, errors.New("offset must be nonnegative and limit must be at most 500")
	}
	if limit == 0 {
		limit = 100
	}
	if offset > len(items) {
		offset = len(items)
	}
	next, size := offset, 2
	page := []T{}
	for next < len(items) && len(page) < limit {
		encoded, err := json.Marshal(items[next])
		if err != nil {
			return nil, 0, 0, err
		}
		if len(encoded)+2 > maxBytes {
			if len(page) > 0 {
				break
			}
			return nil, 0, 0, errors.New("one item exceeds the page size limit")
		}
		extra := len(encoded)
		if len(page) > 0 {
			extra++
		}
		if size+extra > maxBytes {
			break
		}
		size += extra
		page = append(page, items[next])
		next++
	}
	return page, offset, next, nil
}

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
		extra := len(encoded)
		if len(out.Connections) > 0 {
			extra++
		}
		if encodedBytes+extra > maxAgentPageBytes {
			break
		}
		encodedBytes += extra
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
	return a.agentGroupsPage(agent.PageArgs{})
}

func (a *App) agentGroupNodes(in agent.GroupNodesArgs) (agent.GroupNodesResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return agent.GroupNodesResult{}, errors.New("core is not running")
	}
	if in.Group == "" {
		return agent.GroupNodesResult{}, errors.New("group is required")
	}
	g, err := a.core.Group(in.Group)
	if err != nil {
		return agent.GroupNodesResult{}, err
	}
	items := make([]agent.ProxyNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		items = append(items, agent.ProxyNode{Name: n.Name, Type: n.Type, UDP: n.UDP})
	}
	page, offset, next, err := boundedAgentPage(items, in.Offset, in.Limit, maxAgentPageBytes/2)
	if err != nil {
		return agent.GroupNodesResult{}, err
	}
	return agent.GroupNodesResult{Group: g.Name, Total: len(items), Offset: offset, NextOffset: next, Nodes: page}, nil
}

func (a *App) agentGroupsPage(in agent.PageArgs) (agent.GroupsResult, error) {
	if a == nil || a.core == nil || !a.core.Status().Running || a.model == nil {
		return agent.GroupsResult{}, errors.New("core is not running")
	}
	if err := a.loadGroupsWithSelection(false); err != nil {
		return agent.GroupsResult{}, err
	}
	if in.Offset < 0 || in.Limit < 0 || in.Limit > 500 {
		return agent.GroupsResult{}, errors.New("offset must be nonnegative and limit must be at most 500")
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	if in.Offset > len(a.model.Groups) {
		in.Offset = len(a.model.Groups)
	}
	result := agent.GroupsResult{Groups: []agent.ProxyGroup{}, Total: len(a.model.Groups), Offset: in.Offset, NextOffset: in.Offset}
	size := 2
	for result.NextOffset < len(a.model.Groups) && len(result.Groups) < in.Limit {
		row := a.model.Groups[result.NextOffset]
		g, err := a.core.Group(row.Name)
		if err != nil {
			return agent.GroupsResult{}, errors.New("group list changed while reading; retry")
		}
		allNodes := make([]agent.ProxyNode, 0, len(g.Nodes))
		for _, node := range g.Nodes {
			allNodes = append(allNodes, agent.ProxyNode{Name: node.Name, Type: node.Type, UDP: node.UDP})
		}
		nodes, _, next, pageErr := boundedAgentPage(allNodes, 0, 100, maxAgentPageBytes/2)
		out := agent.ProxyGroup{Name: g.Name, Type: g.Type, Current: g.Now, Nodes: nodes, NodesTotal: len(allNodes), NodesTruncated: pageErr != nil || next < len(allNodes)}
		if pageErr != nil {
			out.Nodes = []agent.ProxyNode{}
			out.NodesWarning = "A member is too large to display."
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return agent.GroupsResult{}, err
		}
		if len(encoded)+2 > maxAgentPageBytes {
			if len(result.Groups) > 0 {
				break
			}
			return agent.GroupsResult{}, errors.New("one group exceeds the page size limit")
		}
		extra := len(encoded)
		if len(result.Groups) > 0 {
			extra++
		}
		if size+extra > maxAgentPageBytes {
			break
		}
		size += extra
		result.Groups = append(result.Groups, out)
		result.NextOffset++
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
		extra := len(encoded)
		if len(out.Rules) > 0 {
			extra++
		}
		if encodedBytes+extra > maxAgentPageBytes {
			break
		}
		encodedBytes += extra
		out.Rules = append(out.Rules, rule)
		out.NextOffset++
	}
	return out, nil
}
