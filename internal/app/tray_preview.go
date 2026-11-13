package app

import (
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/egoist/mygo"
	mygoui "github.com/egoist/mygo/ui"
)

// TrayPreviewModel is the menu the tray screenshots draw.
func TrayPreviewSnapshot() TraySnapshot {
	return TraySnapshot{
		Mode:         "rule",
		SystemProxy:  true,
		TUN:          false,
		TUNAvailable: false,
		Version:      ui.AppVersion,
		Profiles:     []TrayProfile{{Name: "示例订阅", Current: true}},
		Groups:       []TrayGroup{{Name: "Proxy", Now: "香港 01", Nodes: []string{"香港 01", "DIRECT"}}},
	}
}

// TrayMenuView draws the macOS tray menu, with the outbound-mode submenu open.
// It is the headless stand-in for a native menu screenshot.
func TrayMenuView(snap TraySnapshot, dark bool) func(*mygoui.Context) {
	return func(c *mygoui.Context) {
		pal := ui.PaletteFor(dark)
		c.SetTheme(pal.Theme())
		c.Root().Background(pal.Content)
		menu := BuildTrayMenu(snap, TrayActions{})
		mygoui.Row(c).Padding(16).Gap(4).AlignItems(mygoui.Start).Children(func() {
			drawTrayMenu(c, pal, menu.Items(), "tray-menu")
			for _, it := range menu.Items() {
				if it != nil && it.ID == "modes" {
					drawTrayMenu(c, pal, it.Submenu, "tray-modes")
				}
			}
		})
	}
}

func drawTrayMenu(c *mygoui.Context, pal ui.Palette, items []*mygo.MenuItem, id string) {
	bg := mygoui.Hex("#F4F4F4")
	if pal.Dark {
		bg = mygoui.Hex("#2C2C2E")
	}
	mygoui.Column(c).Padding(4, 0).Radius(8).Background(bg).Border(1, pal.Divider).MinWidth(240).Label(id).Children(func() {
		for _, it := range items {
			if it == nil {
				continue
			}
			if it.Type == mygo.MenuItemSeparator {
				mygoui.Box(c).Height(1).FillWidth().Margin(4, 8).Background(pal.Divider)
				continue
			}
			fg := pal.Text
			if it.Disabled {
				fg = pal.TextMuted
			}
			mygoui.Row(c).Height(22).Padding(0, 10).Gap(8).AlignItems(mygoui.Center).Children(func() {
				mark := " "
				if it.Checked {
					mark = "✓"
				}
				mygoui.Text(c, mark).FontSize(12).Width(12).TextColor(fg)
				mygoui.Text(c, it.Label).FontSize(13).TextColor(fg).Grow(1)
				if len(it.Submenu) > 0 {
					mygoui.Text(c, "›").FontSize(14).TextColor(pal.TextMuted)
				}
			})
		}
	})
}
