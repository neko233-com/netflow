package app

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/constant/features"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/kernelopts"
)

func (a *App) agentKernelOptions() (agent.KernelOptionsResult, error) {
	if a.kernelOptions == nil {
		return agent.KernelOptionsResult{}, errors.New("kernel options are unavailable")
	}
	if err := a.kernelOptions.CheckCurrent(); err != nil {
		return agent.KernelOptionsResult{}, err
	}
	result := agent.KernelOptionsResult{Overrides: a.kernelOptions.Snapshot()}
	if a.core != nil {
		status := a.core.Status()
		if status.Running {
			result.Effective = &agent.KernelEffective{Mode: status.Mode, AllowLAN: status.AllowLAN, IPv6: status.IPv6, UnifiedDelay: status.UnifiedDelay, LogLevel: status.LogLevel, MixedPort: status.MixedPort, SOCKSPort: status.SOCKSPort, HTTPPort: status.HTTPPort}
		}
	}
	return result, nil
}

func (a *App) agentSetKernelOption(input agent.KernelOptionArgs) (agent.KernelOptionsResult, error) {
	next, err := a.agentKernelOptionCandidate(input)
	if err != nil {
		return agent.KernelOptionsResult{}, err
	}
	if err = a.applyKernelOptions(next); err != nil {
		return agent.KernelOptionsResult{}, err
	}
	return a.agentKernelOptions()
}

func (a *App) agentKernelOptionCandidate(input agent.KernelOptionArgs) (kernelopts.Options, error) {
	current, err := a.agentKernelOptions()
	if err != nil {
		return kernelopts.Options{}, err
	}
	count := 0
	if input.BoolValue != nil {
		count++
	}
	if input.StringValue != nil {
		count++
	}
	if input.PortValue != nil {
		count++
	}
	if (input.Inherit && count != 0) || (!input.Inherit && count != 1) {
		return kernelopts.Options{}, errors.New("specify inherit or exactly one typed option value")
	}
	next := current.Overrides
	switch input.Name {
	case "allow-lan", "ipv6", "unified-delay":
		if !input.Inherit && input.BoolValue == nil {
			return kernelopts.Options{}, errors.New("boolean value required")
		}
		switch input.Name {
		case "allow-lan":
			next.AllowLAN = input.BoolValue
		case "ipv6":
			next.IPv6 = input.BoolValue
		case "unified-delay":
			next.UnifiedDelay = input.BoolValue
		}
	case "log-level", "tun-stack":
		if !input.Inherit && input.StringValue == nil {
			return kernelopts.Options{}, errors.New("string value required")
		}
		if input.Name == "log-level" {
			next.LogLevel = input.StringValue
		} else {
			if input.StringValue != nil && (*input.StringValue == "mixed" || *input.StringValue == "gvisor") && !features.WithGVisor {
				return kernelopts.Options{}, errors.New("this build does not include gVisor")
			}
			next.TUNStack = input.StringValue
		}
	case "mixed-port", "socks-port", "http-port":
		if !input.Inherit && input.PortValue == nil {
			return kernelopts.Options{}, errors.New("port value required")
		}
		switch input.Name {
		case "mixed-port":
			if a.settings.SystemProxy {
				return kernelopts.Options{}, errors.New("restore the legacy system proxy before changing its port")
			}
			next.MixedPort = input.PortValue
		case "socks-port":
			next.SOCKSPort = input.PortValue
		case "http-port":
			next.HTTPPort = input.PortValue
		}
	default:
		return kernelopts.Options{}, fmt.Errorf("unknown kernel option %q", input.Name)
	}
	return next, nil
}
