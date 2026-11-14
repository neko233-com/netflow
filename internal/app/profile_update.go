package app

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
)

// UpdateProfile replaces one remote subscription only after it has been
// downloaded and validated. A failed reload restores the previous files.
func (a *App) UpdateProfile(uid string) error {
	if a.profileUpdates[uid] {
		return errors.New("订阅正在更新")
	}
	item, err := a.profileItem(uid)
	if err != nil {
		return err
	}
	client, err := a.subscriptionClient(item.Option, false)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	result, err := fetchProfileResponse(item.URL, client, item.Option.UserAgent)
	if err != nil {
		return err
	}
	return a.updateProfileData(uid, item.URL, result.body, result.headers)
}

func (a *App) profileURL(uid string) (string, error) {
	item, err := a.profileItem(uid)
	return item.URL, err
}

func (a *App) profileItem(uid string) (profile.CatalogItem, error) {
	if a == nil || a.profiles == nil {
		return profile.CatalogItem{}, errors.New("订阅存储不可用")
	}
	f, err := a.profiles.Load()
	if err != nil {
		return profile.CatalogItem{}, err
	}
	for _, item := range f.Items {
		if item.UID == uid && item.URL != "" {
			return item, nil
		}
	}
	return profile.CatalogItem{}, errors.New("远程订阅不存在")
}

func (a *App) updateProfileData(uid, expectedURL string, body []byte, headers http.Header) error {
	f, err := a.profiles.Load()
	if err != nil {
		return err
	}
	index := -1
	for i := range f.Items {
		if f.Items[i].UID == uid {
			index = i
			break
		}
	}
	if index < 0 || f.Items[index].URL == "" || f.Items[index].URL != expectedURL {
		return errors.New("订阅已删除或链接已变化，请重新更新")
	}
	if err = validateProfile(body); err != nil {
		return err
	}
	rel := f.Items[index].File
	oldFile, _, err := readProfileFile(a.dir, rel)
	if err != nil {
		return err
	}
	active := f.Current == uid
	if active {
		if err = a.validateEffectiveProfile(body, uid); err != nil {
			return err
		}
	}
	var oldConfig []byte
	var nextConfig []byte
	configUpdated := false
	if active {
		oldConfig, err = safepath.ReadFile(a.dir, "config.yaml")
		if err != nil {
			return err
		}
		nextConfig = profile.EnsureMixedPort(body, 7897)
	}
	if err = safepath.CompareAndWrite(a.dir, rel, oldFile, body); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []error
		if e := safepath.CompareAndWrite(a.dir, rel, body, oldFile); e != nil {
			failures = append(failures, e)
		}
		if configUpdated {
			if e := safepath.CompareAndWrite(a.dir, "config.yaml", nextConfig, oldConfig); e != nil {
				failures = append(failures, e)
			}
			if a.core != nil && a.core.Status().Running {
				if e := a.core.Reload(); e != nil {
					failures = append(failures, e)
				}
			}
		}
		if len(failures) > 0 {
			return errors.Join(cause, fmt.Errorf("恢复旧配置失败: %w", errors.Join(failures...)))
		}
		return cause
	}
	if active {
		if err = safepath.CompareAndWrite(a.dir, "config.yaml", oldConfig, nextConfig); err != nil {
			return rollback(err)
		}
		configUpdated = true
		if a.core != nil && a.core.Status().Running {
			if err = a.core.Reload(); err != nil {
				return rollback(err)
			}
		}
	}
	f.Items[index].Updated = time.Now().UTC().Truncate(time.Second)
	profile.ApplySubscriptionUserInfo(&f.Items[index], headers)
	if err = a.profiles.Save(f); err != nil {
		return rollback(err)
	}
	a.loadProfiles()
	if active {
		a.loadGroups()
		a.refreshHome()
	}
	return nil
}
