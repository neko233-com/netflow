package app

import (
	_ "embed"
	"log"
	"runtime"

	"github.com/egoist/mygo"
	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/ui"
)

// Run prepares the kernel and runs the native event loop until quit.
func (a *App) Run() error {
	if err := a.Prepare(); err != nil {
		return err
	}
	mygo.App.SetName("NetFlow")
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	var quitting bool
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { quitting = true })
	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
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
		Hidden:         a.model.Prefs.SilentStart,
		Content:        mygoui.View(a.model.View),
	})
	a.model.Hooks.ImportURLAsync = a.importURLAsync
	a.model.Hooks.UpdateProfileAsync = a.updateProfileAsync
	a.model.Hooks.BrowseProfiles = a.browseProfiles
	a.model.Hooks.CreateProfileAsync = a.createProfileAsync
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
		if a.model.Prefs.SilentStart {
			a.win.Show()
		}
		return
	}
	a.tray = tray
	tray.OnClick(func() { a.trayClick() })
}

func (a *App) trayClick() {
	switch a.model.Prefs.TrayEvent {
	case "tray_menu":
		if a.tray != nil {
			a.tray.PopUpMenu()
		}
	case "system_proxy":
		_ = a.SetSystemProxy(!a.settings.SystemProxy)
	case "tun":
		_ = a.SetTUN(!a.settings.TUN)
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
	a.win.Show()
	a.win.Focus()
}

//go:embed assets/tray.png
var trayArtwork []byte

func trayIcon() []byte { return trayArtwork }
