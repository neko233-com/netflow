package app

import (
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/clashlog"
	"github.com/neko233-com/netflow/internal/rules"
	"github.com/egoist/mygo"
)

func (a *App) closeConnection(id string) error {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return nil
	}
	return a.core.CloseConnection(id)
}

func (a *App) closeAllConnections() error {
	if a == nil || a.core == nil || !a.core.Status().Running {
		return nil
	}
	return a.core.CloseAllConnections()
}

func (a *App) refreshRules() ([]rules.Item, []rules.Provider) {
	if a == nil || a.core == nil {
		return nil, nil
	}
	return a.core.Rules(), a.core.RuleProviders()
}

func (a *App) updateRuleProvider(name string) error {
	if a == nil || a.core == nil {
		return errors.New("core is nil")
	}
	return a.core.UpdateRuleProvider(name)
}

func (a *App) startLive() {
	if a.logs == nil {
		a.logs = clashlog.NewBuffer()
	}
	if a.core != nil && a.stopLogs == nil {
		a.stopLogs = a.core.SubscribeLogs(func(level, payload string) {
			a.logs.Add(level, payload, time.Now())
		})
	}
	if a.liveStop != nil {
		return
	}
	a.liveStop = make(chan struct{})
	go a.liveLoop(a.liveStop)
}

func (a *App) stopLive() {
	if a.stopLogs != nil {
		a.stopLogs()
		a.stopLogs = nil
	}
	if a.liveStop != nil {
		close(a.liveStop)
		a.liveStop = nil
	}
}

func (a *App) liveLoop(stop <-chan struct{}) {
	tick := time.NewTicker(clashlog.BatchWindow)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			n++
			sampleConn := n%10 == 0
			mygo.RunOnMain(func() {
				if a.model == nil || a.logs == nil {
					return
				}
				a.logs.SetPaused(a.model.Logs.Paused)
				a.logs.Flush(time.Now())
				a.model.Logs.Lines = a.logs.Lines()
				if sampleConn && a.core != nil {
					active, up, down := a.core.Connections()
					snap := a.connTrack.Observe(active, up, down, time.Now())
					a.model.Conns.Active = snap.Active
					a.model.Conns.Closed = snap.Closed
					a.model.Conns.Up = snap.UploadTotal
					a.model.Conns.Down = snap.DownloadTotal
				}
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		}
	}
}
