package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

// UpdateProfile replaces one remote subscription only after it has been
// downloaded and validated. A failed reload restores the previous files.
func (a *App) UpdateProfile(uid string) error {
	if a == nil || a.profiles == nil {
		return errors.New("订阅存储不可用")
	}
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
	if index < 0 || f.Items[index].URL == "" {
		return errors.New("远程订阅不存在")
	}
	body, err := fetchProfile(f.Items[index].URL)
	if err != nil {
		return err
	}
	if err = validateProfile(body); err != nil {
		return err
	}
	file := filepath.Join(a.dir, f.Items[index].File)
	inside, err := filepath.Rel(filepath.Join(a.dir, "profiles"), file)
	if err != nil || inside == "." || inside == ".." || filepath.IsAbs(inside) || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return errors.New("订阅文件路径无效")
	}
	oldFile, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	active := f.Current == uid
	configPath := filepath.Join(a.dir, "config.yaml")
	var oldConfig []byte
	if active {
		oldConfig, err = os.ReadFile(configPath)
		if err != nil {
			return err
		}
	}
	if err = os.WriteFile(file, body, 0600); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []error
		if e := os.WriteFile(file, oldFile, 0600); e != nil {
			failures = append(failures, e)
		}
		if active {
			if e := os.WriteFile(configPath, oldConfig, 0600); e != nil {
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
		if err = os.WriteFile(configPath, profile.EnsureMixedPort(body, 7897), 0600); err != nil {
			return rollback(err)
		}
		if a.core != nil && a.core.Status().Running {
			if err = a.core.Reload(); err != nil {
				return rollback(err)
			}
		}
	}
	f.Items[index].Updated = time.Now().UTC().Truncate(time.Second)
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
