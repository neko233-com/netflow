package app

import (
	"errors"
	"runtime"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/clashlog"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/rules"
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
					a.updateTraffic(snap)
					if !a.started.IsZero() {
						a.model.Home.Uptime = time.Since(a.started)
					}
					if n%40 == 0 {
						var mem runtime.MemStats
						runtime.ReadMemStats(&mem)
						a.model.Home.Memory = int64(mem.Alloc)
					}
				}
				if n%20 == 0 {
					a.model.TickIP()
				}
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		}
	}
}

func (a *App) updateTraffic(snap conn.Snapshot) {
	if a.model == nil {
		return
	}
	a.model.Conns.Active = snap.Active
	a.model.Conns.Closed = snap.Closed
	a.model.Conns.Up = snap.UploadTotal
	a.model.Conns.Down = snap.DownloadTotal
	a.model.Home.TotalUp = snap.UploadTotal
	a.model.Home.TotalDown = snap.DownloadTotal
	a.model.Home.UpSpeed = snap.UploadSpeed
	a.model.Home.DownSpeed = snap.DownloadSpeed
	a.model.Home.Connections = len(snap.Active)
}
