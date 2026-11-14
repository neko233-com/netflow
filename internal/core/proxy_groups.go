package core

import (
	"errors"
	"fmt"
	"sort"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

type ProxyGroup struct {
	Name, Type, Now, Icon string
	Hidden                bool
	Nodes                 []ProxyNode
}
type ProxyProvider struct {
	Name, Vehicle string
	Count         int
}

var ErrProviderProfileChanged = errors.New("active profile changed before provider update")

// Group returns the current resolved members, including provider-backed nodes.
func (c *Core) Group(name string) (ProxyGroup, error) {
	if c == nil {
		return ProxyGroup{}, errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return ProxyGroup{}, errors.New("core is not running")
	}
	proxy := tunnel.Proxies()[name]
	if proxy == nil {
		return ProxyGroup{}, fmt.Errorf("proxy group %s not found", name)
	}
	group, ok := proxy.Adapter().(outboundgroup.ProxyGroup)
	if !ok {
		return ProxyGroup{}, fmt.Errorf("%s is not a proxy group", name)
	}
	out := ProxyGroup{Name: name, Type: proxy.Type().String(), Now: group.Now(), Icon: group.Icon(), Hidden: group.Hidden()}
	for _, member := range group.Proxies() {
		if member == nil {
			continue
		}
		info := member.ProxyInfo()
		out.Nodes = append(out.Nodes, ProxyNode{Name: member.Name(), Type: member.Type().String(), UDP: member.SupportUDP(), TFO: info.TFO, XUDP: info.XUDP, MPTCP: info.MPTCP, SMUX: info.SMUX})
	}
	return out, nil
}

func (c *Core) ProxyProviders() []ProxyProvider {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	var out []ProxyProvider
	for name, p := range tunnel.Providers() {
		if p == nil || p.VehicleType() == P.Compatible {
			continue
		}
		out = append(out, ProxyProvider{Name: name, Vehicle: p.VehicleType().String(), Count: p.Count()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *Core) UpdateProxyProvider(name string) error {
	return c.updateProxyProvider(name, nil)
}

func (c *Core) UpdateProxyProviderForProfile(name, profileID string) error {
	return c.updateProxyProvider(name, &profileID)
}

func (c *Core) updateProxyProvider(name string, expected *string) error {
	if c == nil {
		return errors.New("core is nil")
	}
	c.mu.Lock()
	if expected != nil && c.profileID != *expected {
		c.mu.Unlock()
		return ErrProviderProfileChanged
	}
	running := c.running
	var p P.ProxyProvider
	if running {
		p = tunnel.Providers()[name]
	}
	c.mu.Unlock()
	if !running {
		return errors.New("core is not running")
	}
	if p == nil || p.VehicleType() == P.Compatible {
		return fmt.Errorf("proxy provider %s not found", name)
	}
	return p.Update()
}
