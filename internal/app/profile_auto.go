package app

import (
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/profile"
)

const autoRetryDelay = 15 * time.Minute

func profileUpdateDue(item profile.CatalogItem, now time.Time, retry time.Time) bool {
	if item.Type != "remote" || item.URL == "" || !item.Option.AllowAutoUpdate || now.Before(retry) {
		return false
	}
	minutes := item.Option.UpdateInterval
	if minutes <= 0 || minutes > 43200 {
		minutes = 1440
	}
	return item.Updated.IsZero() || !now.Before(item.Updated.Add(time.Duration(minutes)*time.Minute))
}

func (a *App) startProfileAuto() {
	if a.profileAutoStop != nil {
		return
	}
	a.profileAutoStop = make(chan struct{})
	a.profileAutoRetry = make(map[string]time.Time)
	stop := a.profileAutoStop
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				mygo.RunOnMain(func() { a.autoUpdateOne(now) })
			}
		}
	}()
}

func (a *App) autoUpdateOne(now time.Time) {
	if a.model == nil || a.profiles == nil || a.model.ProfileBusy {
		return
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		a.model.Notice = "读取自动更新计划失败: " + err.Error()
		return
	}
	for _, item := range catalog.Items {
		if !profileUpdateDue(item, now, a.profileAutoRetry[item.UID]) {
			continue
		}
		a.model.ProfileBusy = true
		uid, name := item.UID, item.Name
		a.updateProfileAsync(uid, func(err error) {
			a.model.ProfileBusy = false
			if err != nil {
				a.profileAutoRetry[uid] = time.Now().Add(autoRetryDelay)
				a.model.Notice = "订阅自动更新失败：" + name + "：" + err.Error()
			} else {
				delete(a.profileAutoRetry, uid)
				a.model.Notice = "订阅已自动更新：" + name
			}
		})
		return
	}
}
