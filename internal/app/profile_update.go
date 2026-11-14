package app

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptmeta"
)

// UpdateProfile replaces one remote subscription only after it has been
// downloaded and validated. A failed reload restores the previous files.
func (a *App) UpdateProfile(uid string) error {
	if a.tunBusy {
		return errors.New("虚拟网卡正在切换，请稍后重试")
	}
	if a.profileUpdates[uid] {
		return errors.New("订阅正在更新")
	}
	item, err := a.profileItem(uid)
	if err != nil {
		return err
	}
	source, err := a.snapshotProfileSource(item.File)
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
	return a.updateProfileDataWithSource(uid, item.URL, item.URL, result.body, result.headers, &source)
}

type profileSourceSnapshot struct {
	file string
	hash [32]byte
}

// Snapshot the pre-download file without retaining large subscription files in
// memory. A subsequent commit rejects changes to either the path or contents.
func (a *App) snapshotProfileSource(relative string) (profileSourceSnapshot, error) {
	f, _, err := openProfileHandle(a.dir, relative)
	if err != nil {
		return profileSourceSnapshot{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil {
		return profileSourceSnapshot{}, err
	}
	if n > 128<<20 {
		return profileSourceSnapshot{}, errors.New("订阅文件过大")
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return profileSourceSnapshot{file: relative, hash: sum}, nil
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
	return a.updateProfileDataWithURL(uid, expectedURL, expectedURL, body, headers)
}

func (a *App) updateProfileDataWithURL(uid, expectedURL, nextURL string, body []byte, headers http.Header) error {
	return a.updateProfileDataWithSource(uid, expectedURL, nextURL, body, headers, nil)
}

func (a *App) updateProfileDataWithSource(uid, expectedURL, nextURL string, body []byte, headers http.Header, source *profileSourceSnapshot) error {
	if a.tunBusy {
		return errors.New("虚拟网卡正在切换，请稍后重试")
	}
	if !profile.ValidURL(nextURL) {
		return profile.ErrInvalidURL
	}
	f, snapshot, err := a.profiles.LoadForUpdate()
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
	rel := f.Items[index].File
	oldFile, _, err := readProfileFile(a.dir, rel)
	if err != nil {
		return err
	}
	if source != nil && (source.file != rel || source.hash != sha256.Sum256(oldFile)) {
		return errors.New("订阅文件在下载期间已变化，请检查后重试")
	}
	// Script approvals bind the exact subscription and profile name. Updating
	// an inactive profile used to bypass effective-config validation and leave
	// its approval unusable on the next activation. URL replacement can also
	// normalize the name, so it needs the same protection even for equal bytes.
	if f.Items[index].Option.VergeScriptApproval != nil && (!bytes.Equal(body, oldFile) || nextURL != expectedURL) {
		if nextURL != expectedURL {
			return errors.New("已启用的 Verge 脚本绑定当前订阅；更换链接前请先关闭脚本，再重新预览并启用")
		}
		return errors.New("已启用的 Verge 脚本绑定当前订阅；请在脚本对话框预览订阅更新并应用，或先关闭脚本再更新")
	}
	// A disabled script can still be the previous rollback target. Preserve
	// its original subscription and metadata before updating that file.
	item := &f.Items[index]
	if previous := item.Option.VergeScriptPrevious; item.Option.VergeScriptApproval == nil && previous != nil && previous.Approval != nil && previous.Subscription == nil && (!bytes.Equal(body, oldFile) || nextURL != expectedURL) {
		copy := *previous
		copy.Subscription = &scriptmeta.SubscriptionSnapshot{File: item.File, URL: item.URL, Name: item.Name, Updated: item.Updated, Used: item.Used, Total: item.Total, Expire: item.Expire}
		item.Option.VergeScriptPrevious = &copy
	}
	shared, err := a.profiles.SharedProfileFile(f, uid)
	if err != nil {
		return err
	}
	active := f.Current == uid
	rawErr := validateProfile(body)
	if rawErr != nil {
		if !f.Items[index].Option.VergeExtensions {
			return rawErr
		}
		if err := validateProfileShape(body); err != nil {
			return err
		}
	}
	// A Verge data extension can define groups/providers referenced by the
	// subscription. If raw kernel parsing fails, validate the complete composed
	// configuration even for an inactive profile before replacing its file.
	if active || rawErr != nil {
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
	writeRel := rel
	var created *safepath.Created
	if shared {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		writeRel = filepath.Join("profiles", "netflow-"+hex.EncodeToString(nonce[:])+".yaml")
		var createErr error
		created, createErr = safepath.CreateExclusive(a.dir, writeRel, body, false)
		if createErr != nil {
			return createErr
		}
		defer created.Close()
	} else if err = safepath.CompareAndWrite(a.dir, rel, oldFile, body); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []error
		var e error
		if shared {
			e = created.RemoveIfUnchanged(body)
		} else {
			e = safepath.CompareAndWrite(a.dir, rel, body, oldFile)
		}
		if e != nil {
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
	if shared {
		current, _, readErr := readProfileFile(a.dir, rel)
		if readErr != nil || !bytes.Equal(current, oldFile) {
			return rollback(errors.New("共享订阅文件已变化，请重试"))
		}
	}
	f.Items[index].File = writeRel
	// An older release could derive a name containing the old URL's secrets.
	// Normalize that legacy default before changing the URL used to recognize it.
	if nextURL != expectedURL {
		f.Items[index].Name = profile.SafeDisplayName(f.Items[index])
	}
	f.Items[index].URL = nextURL
	f.Items[index].Updated = time.Now().UTC().Truncate(time.Second)
	profile.ApplySubscriptionUserInfo(&f.Items[index], headers)
	if err = a.profiles.SaveIfUnchanged(f, snapshot); err != nil {
		return rollback(err)
	}
	a.loadProfiles()
	if active {
		a.loadGroups()
		a.refreshHome()
	}
	return nil
}
