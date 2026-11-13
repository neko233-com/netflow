package app

import (
	"fmt"
	"strings"

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
				if err == nil && (strings.TrimSpace(form.Name) != "" || strings.TrimSpace(form.Desc) != "") {
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
						if saveErr := a.saveProfileMetadata(item.UID, name, form.Desc); saveErr != nil {
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
