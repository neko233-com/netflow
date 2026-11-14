package app

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/ui"
)

// Only network I/O runs in a worker; catalog/core/model changes remain on
// the native UI thread so concurrent user and Agent actions stay serialized.
func (a *App) importURLAsync(raw string, done func(error)) {
	go func() {
		client := newSubscriptionClient("", 20*time.Second, false)
		defer client.CloseIdleConnections()
		result, err := fetchProfileResponse(raw, client, "")
		a.runOnMain(func() {
			if err == nil {
				err = a.importURLData(raw, result.body, result.headers)
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
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
	go func() {
		defer client.CloseIdleConnections()
		result, err := fetchProfileResponse(item.URL, client, item.Option.UserAgent)
		a.runOnMain(func() {
			if err == nil {
				err = a.updateProfileData(uid, item.URL, result.body, result.headers)
			}
			delete(a.profileUpdates, uid)
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) updateProfileAsync(uid string, done func(error)) {
	a.updateProfileWithOptionsAsync(uid, false, done)
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
	go func() {
		defer client.CloseIdleConnections()
		result, err := fetchProfileResponse(raw, client, options.UserAgent)
		a.runOnMain(func() {
			uid := ""
			if err == nil {
				uid, err = a.importURLDataConfigured(raw, result.body, result.headers, &metadata)
			}
			done(uid, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}
