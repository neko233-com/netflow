package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/proxychain"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/validation"
)

// composeRuntime is shared by kernel application and chain preflight so an
// externally changed profile extension cannot bypass the validated snapshot.
func (a *App) composeRuntime(base []byte, profileID string) ([]byte, error) {
	var err error
	base, err = a.applyProfileVergeExtensions(base, profileID)
	if err != nil {
		return nil, err
	}
	base, err = a.applyProfileTUN(base)
	if err != nil {
		return nil, err
	}
	base, err = a.applyProfileDNS(base, profileID)
	if err != nil {
		return nil, err
	}
	if a.rewrites != nil {
		state := a.rewrites.Snapshot()
		now := time.Now()
		if rewrite.HasActive(state, profileID, now) {
			base, _, err = rewrite.Compose(base, state, profileID, now)
			if err != nil {
				return nil, err
			}
		}
	}
	if a.kernelOptions != nil {
		base, err = kernelopts.Compose(base, a.kernelOptions.Snapshot())
		if err != nil {
			return nil, err
		}
	}
	return composeActiveChain(base, profileID, a.chain.Load())
}

// activeChain is immutable. A process restart intentionally disconnects it.
type activeChain struct {
	ProfileID string
	Spec      proxychain.Spec
	Previous  string
	Exit      string
	Mode      string
	Nodes     []ui.ProxyNode
}

type chainDraft struct {
	active   *activeChain
	original []byte
	composed []byte
	mode     string
	tun      bool
}

func composeActiveChain(base []byte, profileID string, active *activeChain) ([]byte, error) {
	if active == nil || active.ProfileID != profileID {
		return base, nil
	}
	result, err := proxychain.Compose(base, active.Spec)
	if err != nil {
		return nil, err
	}
	return result.Config, nil
}

func (a *App) prepareChain(target string, nodes []ui.ProxyNode) (chainDraft, error) {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return chainDraft{}, errors.New("内核未运行")
	}
	if a.tunBusy || a.chain.Load() != nil {
		return chainDraft{}, errors.New("虚拟网卡正在切换或代理链已连接")
	}
	if a.rewrites != nil {
		if err := a.rewrites.CheckCurrent(); err != nil {
			return chainDraft{}, err
		}
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return chainDraft{}, err
		}
	}
	status := a.core.Status()
	if status.Mode == "direct" {
		return chainDraft{}, errors.New("直连模式不能启用代理链")
	}
	if status.Mode == "global" {
		target = "GLOBAL"
	}
	group, err := a.core.Group(target)
	if err != nil || !selectorGroup(group.Type) {
		return chainDraft{}, errors.New("请选择有效的可选代理组")
	}
	previous, err := a.core.Selected(target)
	if err != nil {
		return chainDraft{}, err
	}
	hops := make([]proxychain.Hop, 0, len(nodes))
	for i, node := range nodes {
		if node.SourceGroup == "" {
			return chainDraft{}, errors.New("缺少节点所属代理组")
		}
		source, err := a.core.Group(node.SourceGroup)
		if err != nil {
			return chainDraft{}, err
		}
		var actual *core.ProxyNode
		for j := range source.Nodes {
			member := &source.Nodes[j]
			if member.Name == node.Name && member.Provider == node.Provider {
				if actual != nil {
					return chainDraft{}, errors.New("节点名称不唯一，无法安全创建代理链")
				}
				actual = member
			}
		}
		if actual == nil {
			return chainDraft{}, errors.New("节点已变化，请重新选择")
		}
		if !proxychain.SupportedRuntimeType(actual.Type) {
			return chainDraft{}, errors.New("此节点类型不支持代理链")
		}
		switch strings.ToUpper(actual.Name) {
		case "DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE":
			return chainDraft{}, errors.New("代理链必须使用实际代理节点")
		}
		if _, err := a.core.Group(actual.Name); err == nil {
			return chainDraft{}, errors.New("代理组不能作为链式节点")
		}
		if actual.Provider != "" {
			source, ok := a.core.(interface {
				ProviderMembers(string) ([]core.ProxyNode, error)
			})
			if !ok {
				return chainDraft{}, errors.New("内核无法检查集合节点")
			}
			members, err := source.ProviderMembers(actual.Provider)
			if err != nil {
				return chainDraft{}, err
			}
			matches := 0
			for _, member := range members {
				if member.Name == actual.Name {
					matches++
				}
			}
			if matches != 1 {
				return chainDraft{}, errors.New("集合内存在重名节点，无法安全创建代理链")
			}
		}
		if i == 0 && actual.DialerProxy != "" {
			return chainDraft{}, errors.New("入口节点已设置上游代理，请先移除以避免循环")
		}
		hops = append(hops, proxychain.Hop{Name: actual.Name, Provider: actual.Provider})
	}
	spec := proxychain.Spec{Target: target, Hops: hops}
	if err := spec.Validate(); err != nil {
		return chainDraft{}, err
	}
	original, err := a.core.EffectiveConfig()
	if err != nil {
		return chainDraft{}, err
	}
	composed, err := proxychain.Compose(original, spec)
	if err != nil {
		return chainDraft{}, err
	}
	return chainDraft{active: &activeChain{ProfileID: a.core.ProfileID(), Spec: spec, Previous: previous, Exit: composed.Exit, Mode: status.Mode, Nodes: append([]ui.ProxyNode(nil), nodes...)}, original: original, composed: composed.Config, mode: status.Mode, tun: status.TUN}, nil
}

func (a *App) checkChainDraft(d chainDraft, checked validation.Result) error {
	if a.chain.Load() != nil || a.tunBusy || a.core == nil || !a.core.Status().Running || a.core.ProfileID() != d.active.ProfileID || a.core.Status().Mode != d.mode || a.core.Status().TUN != d.tun {
		return errors.New("配置或网络状态已变化，请重新连接")
	}
	if a.rewrites != nil {
		if err := a.rewrites.CheckCurrent(); err != nil {
			return err
		}
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return err
		}
	}
	current, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Equal(current, d.original) {
		return errors.New("配置已变化，请重新连接")
	}
	if err := a.checkAgentSources(checked.Sources); err != nil {
		return err
	}
	if err := a.checkSettingsCurrent(); err != nil {
		return err
	}
	source, err := safepath.ReadFile(a.dir, "config.yaml")
	if err != nil {
		return err
	}
	recomposed, err := a.composeRuntime(source, d.active.ProfileID)
	if err != nil || !bytes.Equal(recomposed, d.original) {
		return errors.New("订阅或规则已变化，请重新连接")
	}
	return nil
}

func (a *App) finishChain(d chainDraft, checked validation.Result) error {
	if err := a.checkChainDraft(d, checked); err != nil {
		return err
	}
	a.chain.Store(d.active)
	rollback := func(cause error) error {
		a.chain.Store(nil)
		if err := a.core.Reload(); err != nil {
			// The actual kernel configuration may be indeterminate after a
			// failed apply and failed restoration. Keep a recoverable session
			// marker instead of falsely reporting a clean disconnect.
			a.chain.Store(d.active)
			if a.model != nil {
				a.model.Chain = ui.ChainState{On: true, Connected: true, Target: d.active.Spec.Target, Nodes: append([]ui.ProxyNode(nil), d.active.Nodes...), Warning: "恢复原代理配置失败，链路状态未知"}
			}
			return errors.Join(cause, fmt.Errorf("恢复原代理配置失败: %w", err))
		}
		return cause
	}
	if err := a.core.Reload(); err != nil {
		return rollback(err)
	}
	if err := a.checkChainRouting(d.active); err != nil {
		return rollback(err)
	}
	_ = a.loadGroupsWithSelection(false)
	if a.model != nil {
		a.model.Chain = ui.ChainState{On: true, Connected: true, Target: d.active.Spec.Target, Nodes: append([]ui.ProxyNode(nil), d.active.Nodes...)}
	}
	a.refreshHome()
	return nil
}

// checkChainRouting reports structural availability, not reachability.
func (a *App) checkChainRouting(active *activeChain) error {
	if active == nil || a.core == nil || !a.core.Status().Running {
		return errors.New("内核未运行")
	}
	if a.core.ProfileID() != active.ProfileID || a.core.Status().Mode != active.Mode {
		return errors.New("订阅或代理模式已变化")
	}
	target, err := a.core.Group(active.Spec.Target)
	if err != nil || len(target.Nodes) != 1 || target.Nodes[0].Name != active.Exit || target.Now != active.Exit {
		return errors.New("目标代理组未使用预期链路")
	}
	prefix := strings.TrimSuffix(active.Exit, fmt.Sprintf("hop_%d", len(active.Spec.Hops)-1))
	for i, hop := range active.Spec.Hops {
		group, err := a.core.Group(fmt.Sprintf("%shop_%d", prefix, i))
		expected := hop.Name
		if hop.Provider == "" {
			expected = fmt.Sprintf("%sproxy_%d", prefix, i)
		}
		if err != nil || len(group.Nodes) != 1 || group.Nodes[0].Name != expected || !proxychain.SupportedRuntimeType(group.Nodes[0].Type) {
			return errors.New("代理链节点不可用或存在重名")
		}
		previous := ""
		if i > 0 {
			previous = fmt.Sprintf("%shop_%d", prefix, i-1)
		}
		if group.Nodes[0].DialerProxy != previous {
			return errors.New("代理链节点未使用预期上游")
		}

	}
	return nil
}

func (a *App) connectChainAsync(target string, nodes []ui.ProxyNode, done func(error)) {
	draft, err := a.prepareChain(target, nodes)
	if err != nil {
		done(err)
		return
	}
	go func() {
		checked, err := validateConfigurations(context.Background(), a.dir, []validation.Config{{ID: draft.active.ProfileID, Body: draft.composed}})
		a.runOnMain(func() {
			if err == nil {
				err = a.finishChain(draft, checked)
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) disconnectChain() error {
	a.chainDisconnectWarning = ""
	active := a.chain.Load()
	if active == nil {
		return nil
	}
	if a.tunBusy {
		return errors.New("虚拟网卡正在切换，请稍后重试")
	}
	if a.core == nil || !a.core.Status().Running {
		a.chain.Store(nil)
		if a.model != nil {
			a.model.Chain = ui.ChainState{}
		}
		return nil
	}
	a.chain.Store(nil)
	if err := a.core.Reload(); err != nil {
		a.chain.Store(active)
		if restoreErr := a.core.Reload(); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("恢复代理链失败: %w", restoreErr))
		}
		return err
	}
	if err := a.core.Select(active.Spec.Target, active.Previous); err != nil {
		group, groupErr := a.core.Group(active.Spec.Target)
		found := false
		if groupErr == nil {
			for _, node := range group.Nodes {
				if node.Name == active.Previous {
					found = true
					break
				}
			}
		}
		if groupErr != nil || !found {
			a.chainDisconnectWarning = "代理链已断开，但原代理组或节点已不存在，无法恢复原选择"
		} else {
			a.chain.Store(active)
			if restoreErr := a.core.Reload(); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("恢复代理链失败: %w", restoreErr))
			}
			return fmt.Errorf("恢复原节点失败: %w", err)
		}
	}
	a.loadGroups()
	if a.model != nil {
		a.model.Chain = ui.ChainState{}
		if a.chainDisconnectWarning != "" {
			a.model.Notice = a.chainDisconnectWarning
		}
	}
	a.refreshHome()
	return nil
}
