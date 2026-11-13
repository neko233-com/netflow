package core

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// TestDelay probes the requested proxy through mihomo, without holding the
// core mutex during network I/O. The returned duration is milliseconds.
func (c *Core) TestDelay(group, name, rawURL string, timeout time.Duration) (int, error) {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return 0, errors.New("测速链接必须是有效的 HTTP 或 HTTPS 地址")
	}
	if timeout <= 0 || timeout > time.Minute {
		return 0, errors.New("测速超时时间无效")
	}
	if c == nil {
		return 0, errors.New("内核不可用")
	}
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return 0, errors.New("内核未运行")
	}
	var proxy C.Proxy
	if group != "" {
		if parent := tunnel.Proxies()[group]; parent != nil {
			if resolved, ok := parent.Adapter().(outboundgroup.ProxyGroup); ok {
				for _, member := range resolved.Proxies() {
					if member != nil && member.Name() == name {
						proxy = member
						break
					}
				}
			}
		}
	}
	if proxy == nil && group == "" {
		proxy = tunnel.Proxies()[name]
	}
	c.mu.Unlock()
	if proxy == nil {
		return 0, fmt.Errorf("找不到节点 %s", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ms, err := proxy.URLTest(ctx, rawURL, nil)
	if err != nil {
		return 0, err
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if ms == 0 {
		return 0, errors.New("测速未返回有效结果")
	}
	return int(ms), nil
}
