package app

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/ui"
)

// Only network I/O runs in a worker; catalog/core/model changes remain on
// the native UI thread so concurrent user and Agent actions stay serialized.
func (a *App) importURLAsync(raw string, done func(error)) {
	go func() {
		body, err := fetchProfile(raw)
		mygo.RunOnMain(func() {
			if err == nil {
				err = a.importURLData(raw, body)
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
	raw, err := a.profileURL(uid)
	if err != nil {
		done(err)
		return
	}
	if a.core == nil {
		done(fmt.Errorf("内核未运行，无法通过代理更新"))
		return
	}
	st := a.core.Status()
	if !st.Running || st.MixedPort <= 0 {
		done(fmt.Errorf("内核混合端口不可用，无法通过代理更新"))
		return
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(st.MixedPort))
	go func() {
		body, err := fetchProfileThroughProxy(raw, addr)
		mygo.RunOnMain(func() {
			if err == nil {
				err = a.updateProfileData(uid, raw, body)
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func fetchProfileThroughProxy(raw, addr string) ([]byte, error) {
	proxy := &url.URL{Scheme: "http", Host: addr}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	return fetchProfileWithClient(raw, &http.Client{Timeout: 20 * time.Second, Transport: transport})
}

func (a *App) updateProfileAsync(uid string, done func(error)) {
	raw, err := a.profileURL(uid)
	if err != nil {
		done(err)
		return
	}
	go func() {
		body, err := fetchProfile(raw)
		mygo.RunOnMain(func() {
			if err == nil {
				err = a.updateProfileData(uid, raw, body)
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *App) browseProfiles() ([]string, error) {
	return mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "导入本地配置", Multiple: true, Filters: []mygo.FileFilter{{Name: "YAML 配置", Extensions: []string{"yaml", "yml"}}}})
}

func (a *App) createProfileAsync(form ui.ProfileForm, done func(error)) {
	raw := strings.TrimSpace(form.URL)
	go func() {
		body, err := fetchProfile(raw)
		mygo.RunOnMain(func() {
			if err == nil {
				err = a.importURLData(raw, body)
				if err == nil {
					catalog, readErr := a.profiles.Load()
					if readErr != nil {
						err = readErr
					} else if len(catalog.Items) == 0 {
						err = fmt.Errorf("新订阅未出现在目录中")
					} else {
						item := catalog.Items[len(catalog.Items)-1]
						name := strings.TrimSpace(form.Name)
						if name == "" {
							name = item.Name
						}
						form.UID = item.UID
						form.Name = name
						form.Type = "remote"
						if saveErr := a.saveProfileMetadata(form); saveErr != nil {
							err = fmt.Errorf("订阅已导入，但名称或描述保存失败: %w", saveErr)
						}
					}
				}
			}
			done(err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}
