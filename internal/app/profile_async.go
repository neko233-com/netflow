package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/ui"
)

func (a *App) profileRequestContext() context.Context {
	if a.profileContext != nil {
		return a.profileContext
	}
	return context.Background()
}

// Only network I/O runs in a worker; catalog/core/model changes remain on
// the native UI thread so concurrent user and Agent actions stay serialized.
func (a *App) importURLAsync(raw string, done func(error)) {
	ctx := a.profileRequestContext()
	a.profileWorkers.Add(1)
	go func() {
		defer a.profileWorkers.Done()
		client := newSubscriptionClient("", 20*time.Second, false)
		defer client.CloseIdleConnections()
		result, err := fetchProfileResponseContext(ctx, raw, client, "")
		a.runOnMain(func() {
			finish := func(_ string, err error) {
				done(err)
				if a.win != nil {
					a.win.Invalidate()
				}
			}
			if err != nil {
				finish("", err)
				return
			}
			a.importProfileAsync(func() (profile.CatalogItem, bool, error) {
				return a.profiles.ImportRemoteConfigured(raw, func(string) ([]byte, error) { return result.body, nil }, result.headers, nil)
			}, result.body, finish)
		})
	}()
}

// Importing the first profile also activates it. Run that reload as a
// cancelable transaction, so a slow provider cannot block either event loop.
func (a *App) importProfileAsync(importItem func() (profile.CatalogItem, bool, error), body []byte, done func(string, error)) {
	var uid string
	var discarded bool
	a.startGUIConfigOperation("正在导入订阅", func() (*guiConfigTransaction, error) {
		if a.profiles == nil {
			a.profiles = profile.NewStore(a.dir)
		}
		if err := validateProfile(body); err != nil {
			return nil, err
		}
		item, first, err := importItem()
		if err != nil {
			return nil, err
		}
		uid = item.UID
		if !first {
			return &guiConfigTransaction{commit: func() error { a.loadProfiles(); return nil }, rollback: func() (bool, error) { return false, nil }, wrap: profileSwitchError}, nil
		}
		_, catalogSnapshot, err := a.profiles.LoadForUpdate()
		if err != nil {
			return nil, fmt.Errorf("读取导入后的订阅目录失败: %w", err)
		}
		discard := func(err error) error {
			if restoreErr := a.profiles.DiscardFirstImportIfUnchanged(uid, catalogSnapshot, body); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("回滚导入失败: %w", restoreErr))
			}
			discarded = true
			a.loadProfiles()
			return err
		}
		tx, err := a.beginProfileSwitch(uid)
		if err != nil {
			return nil, discard(err)
		}
		return &guiConfigTransaction{
			commit:   func() error { return a.commitProfileSwitch(tx) },
			rollback: func() (bool, error) { return a.beginProfileSwitchRollback(tx) },
			wrap: func(cause, restoreErr error) error {
				if restoreErr != nil {
					return profileSwitchError(cause, restoreErr)
				}
				return discard(cause)
			},
			reload: a.core != nil && a.core.Status().Running,
		}, nil
	}, func(err error) {
		if err != nil && discarded {
			uid = ""
		}
		done(uid, err)
	})
}

func (a *App) importLocalAsync(path string, done func(error)) {
	ctx := a.profileRequestContext()
	a.profileWorkers.Add(1)
	go func() {
		defer a.profileWorkers.Done()
		var body []byte
		f, err := os.Open(path)
		if err == nil {
			body, err = io.ReadAll(io.LimitReader(f, (8<<20)+1))
			_ = f.Close()
			if err == nil && len(body) > 8<<20 {
				err = errors.New("配置文件超过 8 MiB")
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		a.runOnMain(func() {
			finish := func(err error) {
				done(err)
				if a.win != nil {
					a.win.Invalidate()
				}
			}
			if err != nil {
				finish(err)
				return
			}
			a.importProfileAsync(func() (profile.CatalogItem, bool, error) {
				return a.profiles.ImportLocalWithState(path, body)
			}, body, func(_ string, err error) { finish(err) })
		})
	}()
}

// The explicit proxy action never falls back to a direct connection.
func (a *App) updateProfileViaProxyAsync(uid string, done func(error)) {
	a.updateProfileWithOptionsAsync(uid, true, done)
}

func (a *App) subscriptionClient(opt profile.CatalogOption, forceProxy bool) (*http.Client, error) {
	timeout := opt.TimeoutSeconds
	if timeout == 0 {
		timeout = 20
	}
	if timeout < 1 || timeout > 300 {
		return nil, fmt.Errorf("下载超时必须在 1 到 300 秒之间")
	}
	if len(opt.UserAgent) > 512 || strings.ContainsAny(opt.UserAgent, "\r\n") {
		return nil, fmt.Errorf("用户代理无效或超过 512 字节")
	}
	addr := ""
	if opt.UseClashProxy || forceProxy {
		if a.core == nil {
			return nil, fmt.Errorf("内核未运行，无法通过代理更新")
		}
		st := a.core.Status()
		if !st.Running || st.MixedPort <= 0 {
			return nil, fmt.Errorf("内核混合端口不可用，无法通过代理更新")
		}
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(st.MixedPort))
	}
	client := newSubscriptionClient(addr, time.Duration(timeout)*time.Second, opt.AcceptInvalid)
	if opt.UseSystemProxy && !opt.UseClashProxy && !forceProxy {
		if a.proxy == nil {
			return nil, fmt.Errorf("系统代理不可用")
		}
		settings, err := a.proxy.Current()
		if err != nil {
			return nil, fmt.Errorf("读取系统代理失败: %w", err)
		}
		proxy, err := manualSystemProxy(settings)
		if err != nil {
			return nil, err
		}
		client.Transport.(*http.Transport).Proxy = proxy
	}
	return client, nil
}

func newSubscriptionClient(proxyAddr string, timeout time.Duration, acceptInvalid bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if acceptInvalid {
		// This is an explicit, per-subscription user choice.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	if proxyAddr != "" {
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func (a *App) updateProfileWithOptionsAsync(uid string, forceProxy bool, done func(error)) {
	if a.tunBusy {
		done(fmt.Errorf("虚拟网卡正在切换，请稍后重试"))
		return
	}
	if a.profileUpdates[uid] {
		done(fmt.Errorf("订阅正在更新"))
		return
	}
	item, err := a.profileItem(uid)
	if err != nil {
		done(err)
		return
	}
	client, err := a.subscriptionClient(item.Option, forceProxy)
	if err != nil {
		done(err)
		return
	}
	if a.profileUpdates == nil {
		a.profileUpdates = make(map[string]bool)
	}
	a.profileUpdates[uid] = true
	ctx := a.profileRequestContext()
	a.profileWorkers.Add(1)
	go func() {
		defer a.profileWorkers.Done()
		defer client.CloseIdleConnections()
		source, err := a.snapshotProfileSource(item.File)
		var result subscriptionResponse
		if err == nil {
			result, err = fetchProfileResponseContext(ctx, item.URL, client, item.Option.UserAgent)
		}
		a.runOnMain(func() {
			finish := func(err error) {
				delete(a.profileUpdates, uid)
				done(err)
				if a.win != nil {
					a.win.Invalidate()
				}
			}
			if err != nil {
				finish(err)
				return
			}
			a.startGUIConfigOperation("正在更新订阅", func() (*guiConfigTransaction, error) {
				return a.beginProfileUpdate(uid, item.URL, item.URL, result.body, result.headers, &source)
			}, finish)
		})
	}()
}

func (a *App) updateProfileAsync(uid string, done func(error)) {
	a.updateProfileWithOptionsAsync(uid, false, done)
}

// changeProfileURLAsync fetches and validates the new URL before replacing the
// catalog and configuration, retaining the old URL and data on failure.
func (a *App) changeProfileURLAsync(uid, raw string, done func(error)) {
	raw = strings.TrimSpace(raw)
	if a.tunBusy {
		done(fmt.Errorf("虚拟网卡正在切换，请稍后重试"))
		return
	}
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") || !profile.ValidURL(raw) {
		done(profile.ErrInvalidURL)
		return
	}
	if a.profileUpdates[uid] {
		done(fmt.Errorf("订阅正在更新"))
		return
	}
	item, err := a.profileItem(uid)
	if err != nil || item.Type != "remote" {
		done(fmt.Errorf("远程订阅不存在"))
		return
	}
	client, err := a.subscriptionClient(item.Option, false)
	if err != nil {
		done(err)
		return
	}
	if a.profileUpdates == nil {
		a.profileUpdates = make(map[string]bool)
	}
	a.profileUpdates[uid] = true
	ctx := a.profileRequestContext()
	a.profileWorkers.Add(1)
	go func() {
		defer a.profileWorkers.Done()
		defer client.CloseIdleConnections()
		source, err := a.snapshotProfileSource(item.File)
		var result subscriptionResponse
		if err == nil {
			result, err = fetchProfileResponseContext(ctx, raw, client, item.Option.UserAgent)
		}
		a.runOnMain(func() {
			finish := func(err error) {
				delete(a.profileUpdates, uid)
				done(err)
				if a.win != nil {
					a.win.Invalidate()
				}
			}
			if err != nil {
				finish(err)
				return
			}
			a.startGUIConfigOperation("正在更新订阅", func() (*guiConfigTransaction, error) {
				return a.beginProfileUpdate(uid, item.URL, raw, result.body, result.headers, &source)
			}, finish)
		})
	}()
}

func (a *App) browseProfiles() ([]string, error) {
	return mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "导入本地配置", Multiple: true, Filters: []mygo.FileFilter{{Name: "YAML 配置", Extensions: []string{"yaml", "yml"}}}})
}

func (a *App) createProfileAsync(form ui.ProfileForm, done func(error)) {
	a.createProfileWithResult(form, func(_ string, err error) { done(err) })
}

// createProfileWithResult commits metadata with the new catalog entry and
// reports a possible identifier if activation rollback cannot be confirmed.
func (a *App) createProfileWithResult(form ui.ProfileForm, done func(string, error)) {
	if a.tunBusy {
		done("", fmt.Errorf("虚拟网卡正在切换，请稍后重试"))
		return
	}
	raw := strings.TrimSpace(form.URL)
	if form.Timeout < 1 || form.Timeout > 300 || form.Interval < 1 || form.Interval > 43200 {
		done("", fmt.Errorf("下载超时须在 1 到 300 秒之间，更新间隔须在 1 到 43200 分钟之间"))
		return
	}
	options := profile.CatalogOption{UserAgent: strings.TrimSpace(form.UA), TimeoutSeconds: form.Timeout,
		UpdateInterval: form.Interval, AllowAutoUpdate: form.Auto, UseClashProxy: form.Clash, UseSystemProxy: form.SysProxy, AcceptInvalid: form.Insecure}
	metadata := profile.RemoteMetadata{Name: form.Name, Description: form.Desc, Option: options}
	if err := profile.ValidateRemoteMetadata(raw, metadata); err != nil {
		done("", err)
		return
	}
	client, err := a.subscriptionClient(options, false)
	if err != nil {
		done("", err)
		return
	}
	ctx := a.profileRequestContext()
	a.profileWorkers.Add(1)
	go func() {
		defer a.profileWorkers.Done()
		defer client.CloseIdleConnections()
		result, err := fetchProfileResponseContext(ctx, raw, client, options.UserAgent)
		a.runOnMain(func() {
			finish := func(uid string, err error) {
				done(uid, err)
				if a.win != nil {
					a.win.Invalidate()
				}
			}
			if err != nil {
				finish("", err)
				return
			}
			a.importProfileAsync(func() (profile.CatalogItem, bool, error) {
				return a.profiles.ImportRemoteConfigured(raw, func(string) ([]byte, error) { return result.body, nil }, result.headers, &metadata)
			}, result.body, finish)
		})
	}()
}
