package app

import (
	"context"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/update"
)

func (a *App) checkUpdateAsync(done func(update.Result, error)) {
	slots, stop := a.probeSlots, a.probeStop
	go func() {
		select {
		case slots <- struct{}{}:
		case <-stop:
			return
		}
		defer func() { <-slots }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := update.Check(ctx, nil, "", ui.AppVersion)
		mygo.RunOnMain(func() {
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}
