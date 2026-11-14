package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"go.yaml.in/yaml/v3"
)

// Validate the document shape before persisting a subscription. Mihomo also
// validates its full schema when the profile is activated.
func validateProfile(body []byte) error {
	if err := validateProfileShape(body); err != nil {
		return err
	}
	if _, err := executor.ParseWithBytes(profile.EnsureMixedPort(body, 7897)); err != nil {
		return fmt.Errorf("内核配置无效: %w", err)
	}
	return nil
}

// Some Verge subscriptions refer to providers and groups introduced by their
// extensions. Check their document shape first; the complete composed result
// must subsequently pass the offline kernel validator before any commit.
func validateProfileShape(body []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("配置 YAML 无效: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode || len(doc.Content[0].Content) == 0 {
		return errors.New("配置必须是非空的 YAML 映射")
	}
	return nil
}

// Validate the effective configuration before replacing a running profile.
// A system proxy keeps pointing to its original endpoint until disabled.
func (a *App) validateEffectiveProfile(body []byte, profileID string) error {
	return a.validateEffectiveProfileWithDNS(body, profileID, nil)
}

func (a *App) validateEffectiveProfileWithDNS(body []byte, profileID string, dns *dnsOverride) error {
	data := profile.EnsureMixedPort(body, 7897)
	var err error
	data, err = a.applyProfileVergeExtensions(data, profileID)
	if err != nil {
		return err
	}
	data, err = a.applyProfileTUN(data)
	if err != nil {
		return err
	}
	if dns == nil {
		data, err = a.applyProfileDNS(data, profileID)
	} else {
		data, err = composeProfileDNS(data, *dns)
	}
	if err != nil {
		return err
	}
	if a.rewrites != nil {
		state := a.rewrites.Snapshot()
		if rewrite.HasActive(state, profileID, time.Now()) {
			var err error
			data, _, err = rewrite.Compose(data, state, profileID, time.Now())
			if err != nil {
				return err
			}
		}
	}
	if a.kernelOptions != nil {
		var err error
		data, err = kernelopts.Compose(data, a.kernelOptions.Snapshot())
		if err != nil {
			return err
		}
	}
	data, err = composeActiveChain(data, profileID, a.chain.Load())
	if err != nil {
		return err
	}
	cfg, err := executor.ParseWithBytes(data)
	if err != nil {
		return fmt.Errorf("合并后的内核配置无效: %w", err)
	}
	if active := a.chain.Load(); active != nil && active.ProfileID == profileID && cfg.General.Mode.String() != active.Mode {
		return errors.New("请先断开链式代理，再更改代理模式")
	}
	if a.settings.SystemProxy && a.core != nil && a.core.Status().Running && cfg.General.MixedPort != a.core.Status().MixedPort {
		return errors.New("此订阅的混合代理端口不同；请先关闭系统代理或设置统一端口")
	}
	return nil
}
