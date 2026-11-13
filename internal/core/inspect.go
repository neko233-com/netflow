package core

import (
	"errors"
	"strconv"
	"sync"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/rules"

	P "github.com/metacubex/mihomo/constant/provider"
	mihomolog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Connections reads the kernel's active connections and cumulative traffic.
func (c *Core) Connections() ([]conn.Item, int64, int64) {
	if c == nil {
		return nil, 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || statistic.DefaultManager == nil {
		return nil, 0, 0
	}
	snap := statistic.DefaultManager.Snapshot()
	if snap == nil {
		return nil, 0, 0
	}
	out := make([]conn.Item, 0, len(snap.Connections))
	for _, info := range snap.Connections {
		if info == nil {
			continue
		}
		out = append(out, mapConnection(info))
	}
	return out, snap.UploadTotal, snap.DownloadTotal
}

// CloseConnection closes one tracked connection. A missing id is not an error.
func (c *Core) CloseConnection(id string) error {
	if c == nil {
		return errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || statistic.DefaultManager == nil {
		return errors.New("core is not running")
	}
	tr := statistic.DefaultManager.Get(id)
	if tr == nil {
		return nil
	}
	return tr.Close()
}

// CloseAllConnections closes every tracked connection.
func (c *Core) CloseAllConnections() error {
	if c == nil {
		return errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || statistic.DefaultManager == nil {
		return errors.New("core is not running")
	}
	var err error
	statistic.DefaultManager.Range(func(tr statistic.Tracker) bool {
		if tr != nil {
			if closeErr := tr.Close(); err == nil {
				err = closeErr
			}
		}
		return true
	})
	return err
}

func mapConnection(info *statistic.TrackerInfo) conn.Item {
	it := conn.Item{
		ID:          info.UUID.String(),
		Upload:      info.UploadTotal.Load(),
		Download:    info.DownloadTotal.Load(),
		Start:       info.Start,
		Chains:      append([]string(nil), info.Chain...),
		Rule:        info.Rule,
		RulePayload: info.RulePayload,
	}
	if m := info.Metadata; m != nil {
		it.Host = m.Host
		if m.DstIP.IsValid() {
			it.DestinationIP = m.DstIP.String()
		}
		it.RemoteDestination = m.RemoteDst
		if m.DstPort != 0 {
			it.DestinationPort = strconv.Itoa(int(m.DstPort))
		}
		it.Process = m.Process
		it.ProcessPath = m.ProcessPath
		if m.SrcIP.IsValid() {
			it.SourceIP = m.SrcIP.String()
		}
		if m.SrcPort != 0 {
			it.SourcePort = strconv.Itoa(int(m.SrcPort))
		}
		it.Network = m.NetWork.String()
		it.Type = m.Type.String()
	}
	return it
}

// Rules returns the kernel rule list.
func (c *Core) Rules() []rules.Item {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	raw := tunnel.Rules()
	out := make([]rules.Item, 0, len(raw))
	for _, r := range raw {
		if r == nil {
			continue
		}
		out = append(out, rules.Item{Type: r.RuleType().String(), Payload: r.Payload(), Proxy: r.Adapter()})
	}
	return out
}

// RuleProviders returns rule providers sorted by name.
func (c *Core) RuleProviders() []rules.Provider {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	var out []rules.Provider
	for name, p := range tunnel.RuleProviders() {
		if p == nil {
			continue
		}
		out = append(out, rules.Provider{
			Name:     name,
			Vehicle:  p.VehicleType().String(),
			Behavior: p.Behavior().String(),
			Count:    p.Count(),
		})
	}
	return rules.SortProviders(out)
}

// UpdateRuleProvider updates one rule provider.
func (c *Core) UpdateRuleProvider(name string) error {
	if c == nil {
		return errors.New("core is nil")
	}
	c.mu.Lock()
	running := c.running
	var p P.RuleProvider
	if running {
		p = tunnel.RuleProviders()[name]
	}
	c.mu.Unlock()
	if !running {
		return errors.New("core is not running")
	}
	if p == nil {
		return errors.New("rule provider " + name + " not found")
	}
	return p.Update()
}

// UpdateAllRuleProviders updates every provider and returns an error if any fail.
func (c *Core) UpdateAllRuleProviders() error {
	list := c.RuleProviders()
	names := make([]string, len(list))
	for i, p := range list {
		names[i] = p.Name
	}
	return rules.UpdateAll(names, c.UpdateRuleProvider)
}

// SubscribeLogs copies kernel log events to fn until stop is called.
func (c *Core) SubscribeLogs(fn func(level, payload string)) (stop func()) {
	sub := mihomolog.Subscribe()
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer mihomolog.UnSubscribe(sub)
		for {
			select {
			case <-done:
				return
			case ev, ok := <-sub:
				if !ok {
					return
				}
				if fn != nil {
					fn(ev.LogLevel.String(), ev.Payload)
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}
