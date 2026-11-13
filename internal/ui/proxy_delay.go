package ui

import (
	"context"
	"errors"
	"net"
)

const defaultDelayURL = "https://cp.cloudflare.com/generate_204"

func (m *Model) testProxyDelay(group, name, url string) {
	if name == "" {
		return
	}
	if m.Hooks.TestProxyAsync == nil {
		m.Notice = "节点测速不可用"
		return
	}
	var target *ProxyNode
	for i := range m.Groups {
		if m.Groups[i].Name != group {
			continue
		}
		for j := range m.Groups[i].Nodes {
			if m.Groups[i].Nodes[j].Name == name {
				target = &m.Groups[i].Nodes[j]
				break
			}
		}
	}
	if target != nil && target.Delay == DelayTesting {
		return
	}
	if target != nil {
		target.Delay = DelayTesting
	}
	if m.Home.Node.Group == group && m.Home.Node.Name == name {
		m.Home.Node.Delay = DelayTesting
	}
	if url == "" {
		url = defaultDelayURL
	}
	profileID := m.CurrentProfile
	m.Hooks.TestProxyAsync(group, name, url, func(ms int, err error) {
		if m.CurrentProfile != profileID {
			return
		}
		if err != nil {
			var networkError net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
				ms = 0
			} else {
				ms = 100001
			}
		}
		for i := range m.Groups {
			if m.Groups[i].Name != group {
				continue
			}
			for j := range m.Groups[i].Nodes {
				if m.Groups[i].Nodes[j].Name == name && m.Groups[i].Nodes[j].Delay == DelayTesting {
					m.Groups[i].Nodes[j].Delay = ms
				}
			}
		}
		if m.Home.Node.Group == group && m.Home.Node.Name == name && m.Home.Node.Delay == DelayTesting {
			m.Home.Node.Delay = ms
		}
	})
}
