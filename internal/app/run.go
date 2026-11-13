package app

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
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
		Content:        mygoui.View(a.model.View),
	})
	a.startLive()
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

// trayIcon draws a template mark for the menu bar. macOS tints a black
// glyph; other platforms get the same shape in blue so it stays visible.
func trayIcon() []byte {
	const n = 32
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	ink := color.NRGBA{A: 255}
	if runtime.GOOS != "darwin" {
		ink = color.NRGBA{R: 37, G: 99, B: 235, A: 255}
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx := float64(x) - 15.5
			dy := float64(y) - 15.5
			d2 := dx*dx + dy*dy
			if d2 < 13*13 && d2 > 8*8 && dx < 4 {
				img.SetNRGBA(x, y, ink)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
