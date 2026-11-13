package core

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/tunnel"
)

// Select writes node into the named selector group and records it in
// mihomo's selected cache, the same work as PUT /proxies/{group}.
// The kernel must be running. The cache write follows StoreSelected.
func (c *Core) Select(group, node string) error {
	sel, err := c.selector(group)
	if err != nil {
		return err
	}
	if err := sel.Set(node); err != nil {
		return err
	}
	cachefile.Cache().SetSelected(group, node)
	return nil
}

// Selected returns the node the selector currently uses.
func (c *Core) Selected(group string) (string, error) {
	sel, err := c.selector(group)
	if err != nil {
		return "", err
	}
	return sel.Now(), nil
}

type selectableGroup interface {
	outboundgroup.SelectAble
	Now() string
}

func (c *Core) selector(group string) (selectableGroup, error) {
	if c == nil {
		return nil, errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil, errors.New("core is not running")
	}
	p, ok := tunnel.Proxies()[group]
	if !ok || p == nil {
		return nil, fmt.Errorf("proxy group %s not found", group)
	}
	sel, ok := p.Adapter().(selectableGroup)
	if !ok || sel == nil {
		return nil, fmt.Errorf("%s is not a selector", group)
	}
	return sel, nil
}
