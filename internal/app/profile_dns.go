package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/neko233-com/netflow/internal/profile"
)

type dnsOverride struct {
	enabled bool
	text    string
}

func (a *App) applyProfileDNS(data []byte, id string) ([]byte, error) {
	if id == "" || a.profiles == nil {
		return data, nil
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return nil, err
	}
	for _, item := range catalog.Items {
		if item.UID == id {
			if !item.Option.DNSEnabled {
				return data, nil
			}
			return profile.ComposeDNS(data, item.Option.DNSOverride)
		}
	}
	return nil, errors.New("DNS 覆写对应的订阅不存在")
}

func (a *App) setProfileDNS(id string, enabled bool, text string) error {
	if a.profiles == nil || a.core == nil || !a.core.Status().Running || a.core.ProfileID() != id {
		return errors.New("当前订阅或内核不可用")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return err
	}
	index := -1
	for i := range catalog.Items {
		if catalog.Items[i].UID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("订阅不存在")
	}
	if len(text) > 64<<10 {
		return errors.New("DNS 覆写不能超过 64 KiB")
	}
	body, err := os.ReadFile(filepath.Join(a.dir, "config.yaml"))
	if err != nil {
		return err
	}
	if err := a.validateEffectiveProfileWithDNS(body, id, &dnsOverride{enabled: enabled, text: text}); err != nil {
		return err
	}
	old := catalog
	old.Items = append([]profile.CatalogItem(nil), catalog.Items...)
	catalog.Items[index].Option.DNSEnabled = enabled
	catalog.Items[index].Option.DNSOverride = text
	if err := a.profiles.Save(catalog); err != nil {
		return err
	}
	if err := a.core.Reload(); err != nil {
		restore := a.profiles.Save(old)
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
