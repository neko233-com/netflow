package app

import (
	"context"
	"errors"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/ipinfo"
	"github.com/neko233-com/netflow/internal/unlock"
)

func (a *App) queryIPAsync(done func(ipinfo.Result, error)) {
	if a.core == nil || !a.core.Status().Running || a.core.Status().MixedPort == 0 {
		done(ipinfo.Result{}, errors.New("内核代理未运行"))
		return
	}
	endpoint := a.proxyEndpoint()
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		client := unlock.ProxyClient(endpoint, 8*time.Second)
		result, err := ipinfo.Fetch(ctx, client, "")
		mygo.RunOnMain(func() {
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}
