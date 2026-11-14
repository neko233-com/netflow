package app

import (
	"context"
	"errors"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/geoupdate"
)

func (a *App) updateGeoAsync(done func(int, error)) {
	if a.geoBusy {
		done(0, errors.New("GeoData 正在更新"))
		return
	}
	if a.core == nil || a.tunBusy {
		done(0, errors.New("内核不可用或 TUN 正在切换"))
		return
	}
	status := a.core.Status()
	if !status.Running {
		done(0, errors.New("内核未运行"))
		return
	}
	config, err := a.core.EffectiveConfig()
	if err != nil {
		done(0, err)
		return
	}
	dir := a.dir
	a.geoBusy = true
	a.geoLastError = ""
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		count, err := geoupdate.Prepare(ctx, dir, config, status.MixedPort)
		mygo.RunOnMain(func() {
			a.geoBusy = false
			if err != nil {
				a.geoLastError = err.Error()
			} else {
				a.geoRestart = true
			}
			done(count, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}
