package app

import (
	"errors"
	"fmt"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
)

type dnsOverride struct {
	enabled bool
	text    string
	merge   bool
	hosts   string
}

func composeProfileDNS(data []byte, override dnsOverride) ([]byte, error) {
	if !override.enabled {
		return data, nil
	}
	if override.merge {
		return profile.ComposeVergeDNS(data, override.text, override.hosts)
	}
	data, err := profile.ComposeDNS(data, override.text)
	if err != nil || override.hosts == "" {
		return data, err
	}
	return profile.ComposeVergeDNS(data, "", override.hosts)
}

func (a *App) applyProfileDNS(data []byte, id string) ([]byte, error) {
	if id == "" || a.profiles == nil {
		return data, nil
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return nil, err
	}
	return composeProfileDNSFromCatalog(data, id, catalog)
}

func composeProfileDNSFromCatalog(data []byte, id string, catalog profile.File) ([]byte, error) {
	if id == "" {
		return data, nil
	}
	for _, item := range catalog.Items {
		if item.UID == id {
			return composeProfileDNS(data, dnsOverride{enabled: item.Option.DNSEnabled, text: item.Option.DNSOverride, merge: item.Option.DNSVergeMerge, hosts: item.Option.DNSVergeHosts})
		}
	}
	return nil, errors.New("DNS 覆写对应的订阅不存在")
}

func (a *App) stageProfileDNS(id string, enabled bool, text string) (profile.File, []byte, error) {
	if a.tunBusy {
		return profile.File{}, nil, errors.New("虚拟网卡正在切换，请稍后重试")
	}
	if a.profiles == nil || a.core == nil || !a.core.Status().Running || a.core.ProfileID() != id {
		return profile.File{}, nil, errors.New("当前订阅或内核不可用")
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil {
		return profile.File{}, nil, err
	}
	index := -1
	for i := range catalog.Items {
		if catalog.Items[i].UID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return profile.File{}, nil, errors.New("订阅不存在")
	}
	if len(text) > 64<<10 {
		return profile.File{}, nil, errors.New("DNS 覆写不能超过 64 KiB")
	}
	body, err := safepath.ReadFile(a.dir, "config.yaml")
	if err != nil {
		return profile.File{}, nil, err
	}
	option := catalog.Items[index].Option
	merge := option.DNSVergeMerge && text == option.DNSOverride
	if err := a.validateEffectiveProfileWithDNS(body, id, &dnsOverride{enabled: enabled, text: text, merge: merge, hosts: option.DNSVergeHosts}); err != nil {
		return profile.File{}, nil, err
	}
	catalog.Items[index].Option.DNSEnabled = enabled
	catalog.Items[index].Option.DNSOverride = text
	catalog.Items[index].Option.DNSVergeMerge = merge
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		return profile.File{}, nil, err
	}
	return catalog, snapshot, nil
}

func (a *App) setProfileDNS(id string, enabled bool, text string) error {
	catalog, snapshot, err := a.stageProfileDNS(id, enabled, text)
	if err != nil {
		return err
	}
	if err := a.core.Reload(); err != nil {
		restore := a.profiles.RestoreSnapshotIfUnchanged(catalog, snapshot)
		if restore == nil {
			restore = a.core.Reload()
		}
		if restore != nil {
			return errors.Join(err, fmt.Errorf("恢复原 DNS 设置失败: %w", restore))
		}
		return err
	}
	a.loadProfiles()
	a.refreshHome()
	return nil
}

func (a *App) setProfileDNSAsync(id string, enabled bool, text string, done func(error)) {
	a.startGUIConfigOperation("正在应用 DNS 覆写", func() (*guiConfigTransaction, error) {
		catalog, snapshot, err := a.stageProfileDNS(id, enabled, text)
		if err != nil {
			return nil, err
		}
		return &guiConfigTransaction{
			reload: true,
			commit: func() error { a.loadProfiles(); a.refreshHome(); return nil },
			rollback: func() (bool, error) {
				err := a.profiles.RestoreSnapshotIfUnchanged(catalog, snapshot)
				return err == nil, err
			},
			wrap: func(cause, restoreErr error) error {
				if restoreErr != nil {
					return errors.Join(cause, fmt.Errorf("恢复原 DNS 设置失败: %w", restoreErr))
				}
				return cause
			},
		}, nil
	}, done)
}
