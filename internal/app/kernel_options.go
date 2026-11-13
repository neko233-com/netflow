package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/ui"
)

func (a *App) SetKernelOption(name string, value any) error {
	if a == nil || a.kernelOptions == nil {
		return errors.New("内核选项尚未就绪")
	}
	next := a.kernelOptions.Snapshot()
	switch name {
	case "allow-lan", "ipv6", "unified-delay":
		v, ok := value.(bool)
		if !ok {
			return errors.New("选项类型无效")
		}
		switch name {
		case "allow-lan":
			next.AllowLAN = &v
		case "ipv6":
			next.IPv6 = &v
		case "unified-delay":
			next.UnifiedDelay = &v
		}
	case "log-level":
		v, ok := value.(string)
		if !ok {
			return errors.New("日志等级类型无效")
		}
		next.LogLevel = &v
	default:
		return errors.New("未知的内核选项")
	}
	return a.applyKernelOptions(next)
}

func (a *App) SetKernelPorts(p ui.PortSet) error {
	if a == nil || a.kernelOptions == nil {
		return errors.New("内核选项尚未就绪")
	}
	if err := ui.ValidatePorts(p); err != "" {
		return errors.New(err)
	}
	if a.settings.SystemProxy && a.core != nil && p.Mixed != a.core.Status().MixedPort {
		return errors.New("请先关闭系统代理，再修改混合代理端口")
	}
	next := a.kernelOptions.Snapshot()
	mixed, socks, http, redir, tproxy := p.Mixed, 0, 0, 0, 0
	if p.SocksOn {
		socks = p.Socks
	}
	if p.HTTPOn {
		http = p.HTTP
	}
	if p.ShowRedir && p.RedirOn {
		redir = p.Redir
	}
	if p.ShowTProxy && p.TProxyOn {
		tproxy = p.TProxy
	}
	next.MixedPort = &mixed
	next.SOCKSPort = &socks
	next.HTTPPort = &http
	// Do not change listeners hidden on the current platform.
	if p.ShowRedir {
		next.RedirPort = &redir
	}
	if p.ShowTProxy {
		next.TProxyPort = &tproxy
	}
	return a.applyKernelOptions(next)
}

func (a *App) applyKernelOptions(next kernelopts.Options) error {
	if a.core == nil || !a.core.Status().Running {
		return errors.New("内核未运行，无法应用设置")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	base, err := os.ReadFile(filepath.Join(a.dir, "config.yaml"))
	if err != nil {
		return err
	}
	state := a.rewrites.Snapshot()
	if rewrite.HasActive(state, a.core.ProfileID(), time.Now()) {
		base, _, err = rewrite.Compose(base, state, a.core.ProfileID(), time.Now())
		if err != nil {
			return err
		}
	}
	base, err = kernelopts.Compose(base, next)
	if err != nil {
		return err
	}
	cfg, err := executor.ParseWithBytes(base)
	if err != nil {
		return fmt.Errorf("内核配置无效: %w", err)
	}
	used := map[int]bool{}
	for _, port := range []int{cfg.General.MixedPort, cfg.General.Port, cfg.General.SocksPort, cfg.General.RedirPort, cfg.General.TProxyPort} {
		if port > 0 && used[port] {
			return fmt.Errorf("端口 %d 与现有监听端口冲突", port)
		}
		if port > 0 {
			used[port] = true
		}
	}
	old := a.kernelOptions.Snapshot()
	if err = a.kernelOptions.Replace(next); err != nil {
		return err
	}
	if err = a.core.Reload(); err != nil {
		restoreErr := a.kernelOptions.Replace(old)
		if restoreErr == nil {
			restoreErr = a.core.Reload()
		}
		if restoreErr != nil {
			return errors.Join(err, fmt.Errorf("恢复原设置失败: %w", restoreErr))
		}
		return err
	}
	a.refreshHome()
	return nil
}
