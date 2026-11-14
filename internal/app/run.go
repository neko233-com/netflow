package app

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/egoist/mygo"
	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/ui"
)

// Run prepares the kernel and runs the native event loop until quit.
func (a *App) Run() error {
	dir, err := a.dirs.ConfigDir()
	if err != nil {
		return err
	}
	lock, err := appdir.Acquire(dir)
	if errors.Is(err, appdir.ErrAlreadyRunning) {
		// A second launch focuses the existing process rather than allowing
		// two cores to mutate the same subscription and proxy settings.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client := agent.Client{Dir: dir, Timeout: time.Second}
		for {
			if err = client.Call(ctx, "show", nil, nil); err == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return appdir.ErrAlreadyRunning
			case <-time.After(150 * time.Millisecond):
			}
		}
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.Prepare(); err != nil {
		return err
	}
	mygo.App.SetName("NetFlow")
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	var quitting bool
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { quitting = true })
	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
		a.releaseHotkeys()
		if a.profileAutoStop != nil {
			close(a.profileAutoStop)
			a.profileAutoStop = nil
		}
		if a.probeStop != nil {
			close(a.probeStop)
			a.probeStop = nil
		}
		a.stopAgent()
		a.stopLive()
		if a.settings.SystemProxy {
			if restore, ok := a.proxy.(interface{ Restore() error }); ok {
				if err := restore.Restore(); err != nil {
					log.Printf("restore system proxy: %v", err)
				} else {
					a.settings.SystemProxy = false
					if a.store != nil {
						_ = a.store.Save(a.settings)
					}
				}
			}
		}
		if a.tray != nil {
			a.tray.Destroy()
		}
		_ = a.core.Stop()
	})
	mygo.App.OnActivate(func(hasVisible bool) {
		if !hasVisible {
			a.showMain()
		}
	})
	mygo.App.WhenReady(func() { a.ready(&quitting) })
	return mygo.App.Run()
}

func (a *App) ready(quitting *bool) {
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:          "NetFlow",
		Width:          ui.WindowWidth,
		Height:         ui.WindowHeight,
		MinWidth:       ui.WindowMinWidth,
		MinHeight:      ui.WindowMinHeight,
		UseContentSize: true,
		Hidden:         a.model.Prefs.SilentStart || a.model.Prefs.Lightweight,
		Content:        mygoui.View(a.model.View),
	})
	a.model.Hooks.SetTUNAsync = a.requestTUN
	a.model.Hooks.ImportURLAsync = a.importURLAsync
	a.model.Hooks.UpdateProfileAsync = a.updateProfileAsync
	a.model.Hooks.UpdateProfileViaProxyAsync = a.updateProfileViaProxyAsync
	a.model.Hooks.BrowseProfiles = a.browseProfiles
	a.model.Hooks.CreateProfileAsync = a.createProfileAsync
	a.probeSlots = make(chan struct{}, 4)
	a.probeStop = make(chan struct{})
	a.model.Hooks.ProbeSiteAsync = a.probeSiteAsync
	a.model.Hooks.CheckUnlockAsync = a.checkUnlockAsync
	a.model.Hooks.TestProxyAsync = a.testProxyAsync
	a.model.Hooks.UpdateRuleProviderAsync = a.updateRuleProviderAsync
	a.model.Hooks.UpdateProxyProviderAsync = a.updateProxyProviderAsync
	a.model.Hooks.UpdateGeoAsync = a.updateGeoAsync
	a.model.Hooks.CheckUpdateAsync = a.checkUpdateAsync
	a.model.Hooks.QueryIPAsync = a.queryIPAsync
	a.model.Hooks.SystemDark = mygo.Theme.IsDark
	a.shortcuts = mygo.GlobalShortcut
	a.model.Hooks.ApplyHotkeys = a.applyHotkeys
	mygo.Theme.OnUpdated(func() {
		if a.win != nil {
			a.win.Invalidate()
		}
	})
	a.startProfileAuto()
	a.startLive()
	if err := a.startAgent(); err != nil {
		a.model.Notice = "Agent 接口启动失败: " + err.Error()
	}
	a.win.OnClose(func(e *mygo.CloseEvent) {
		if quitting != nil && *quitting {
			return
		}
		e.PreventDefault()
		a.win.Hide()
	})
	mygo.App.SetMenu(mygo.NewMenu([]*mygo.MenuItem{
		{Role: mygo.RoleAppMenu},
		{Label: "文件", Submenu: []*mygo.MenuItem{
			{Label: "显示主窗口", Accelerator: "CmdOrCtrl+Shift+O", Click: func(*mygo.MenuItem, *mygo.Window) { a.showMain() }},
			mygo.Separator(),
			{Role: mygo.RoleClose},
			{Role: mygo.RoleQuit},
		}},
		{Role: mygo.RoleEditMenu},
		{Role: mygo.RoleWindowMenu},
	}))

	menu := BuildTrayMenu(a.traySnapshot(), a.trayActions())
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           trayIcon(),
		IconIsTemplate: runtime.GOOS == "darwin",
		ToolTip:        "NetFlow",
		Menu:           menu,
	})
	if err != nil {
		log.Printf("tray: %v", err)
		// A hidden window must remain reachable if the notification area fails.
		if a.model.Prefs.SilentStart || a.model.Prefs.Lightweight {
			a.win.Show()
		}
		return
	}
	a.tray = tray
	tray.OnClick(func() { a.trayClick() })
	if err := a.configureHotkeys(a.model.Prefs, false); err != nil {
		a.model.Notice = "全局快捷键注册失败: " + err.Error()
	}
}

func (a *App) trayClick() {
	switch a.model.Prefs.TrayEvent {
	case "tray_menu":
		if a.tray != nil {
			a.tray.PopUpMenu()
		}
	case "tun":
		a.requestTUN(!a.settings.TUN, a.tunActionDone)
	case "disable":
		return
	default:
		a.showMain()
	}
}

func (a *App) showMain() {
	if a.win == nil {
		return
	}
	if a.model != nil && a.model.Prefs.Lightweight {
		if err := a.setLightweight(false); err != nil {
			a.model.Notice = err.Error()
		}
	}
	a.win.Show()
	a.win.Focus()
}

func (a *App) setLightweight(on bool) error {
	if a.model == nil || a.win == nil {
		return fmt.Errorf("窗口尚未就绪")
	}
	if on && a.tray == nil {
		return fmt.Errorf("托盘不可用，无法进入轻量模式")
	}
	next := a.model.Prefs
	next.Lightweight = on
	if err := a.savePrefs(next); err != nil {
		return err
	}
	a.model.Prefs = next
	if on {
		a.win.Hide()
	} else {
		a.win.Show()
	}
	if a.tray != nil {
		a.tray.SetMenu(BuildTrayMenu(a.traySnapshot(), a.trayActions()))
	}
	return nil
}

//go:embed assets/tray.png
var trayArtwork []byte

func trayIcon() []byte { return trayArtwork }
