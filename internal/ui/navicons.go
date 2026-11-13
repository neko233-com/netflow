package ui

import mygoui "github.com/egoist/mygo/ui"

// Nav icons follow Clash Verge Rev's outlined Material set
// (design-tokens.md §8.1): Home, Wifi, Dns, Language, ForkRight,
// Subject, LockOpen, Settings. They are monochrome outlines; Icon
// paints them with the row's text color.
func navIcon(id string) *mygoui.SVG {
	if s, ok := navIcons[id]; ok {
		return s
	}
	return navIcons["home"]
}

var navIcons = map[string]*mygoui.SVG{
	"home":          mustNav(navHome),
	"proxies":       mustNav(navWifi),
	"subscriptions": mustNav(navDns),
	"connections":   mustNav(navLanguage),
	"rules":         mustNav(navFork),
	"logs":          mustNav(navSubject),
	"test":          mustNav(navLock),
	"settings":      mustNav(navSettings),
}

func mustNav(src string) *mygoui.SVG {
	return mygoui.MustParseSVG([]byte(src))
}

const navStroke = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">`

const navHome = navStroke + `<path d="M4 11 L12 4 L20 11 V20 H14 V14 H10 V20 H4 Z"/></svg>`

const navWifi = navStroke + `<path d="M4 10 C8 6 16 6 20 10"/><path d="M7 13.5 C9.2 11.2 14.8 11.2 17 13.5"/><path d="M10 16.5 C11 15.6 13 15.6 14 16.5"/><circle cx="12" cy="19" r="1" fill="#000" stroke="none"/></svg>`

const navDns = navStroke + `<circle cx="6" cy="7" r="1.2" fill="#000" stroke="none"/><path d="M10 7 H20"/><circle cx="6" cy="12" r="1.2" fill="#000" stroke="none"/><path d="M10 12 H20"/><circle cx="6" cy="17" r="1.2" fill="#000" stroke="none"/><path d="M10 17 H20"/></svg>`

const navLanguage = navStroke + `<circle cx="12" cy="12" r="8"/><path d="M4 12 H20"/><path d="M12 4 C9 8 9 16 12 20"/><path d="M12 4 C15 8 15 16 12 20"/></svg>`

const navFork = navStroke + `<path d="M7 4 V20"/><path d="M7 12 H16 V20"/><path d="M13 17 L16 20 L19 17"/></svg>`

const navSubject = navStroke + `<path d="M4 7 H20"/><path d="M4 12 H20"/><path d="M4 17 H14"/></svg>`

const navLock = navStroke + `<path d="M8 11 V7 H16 V10"/><rect x="5" y="11" width="14" height="9" rx="1.5"/></svg>`

const navSettings = navStroke + `<circle cx="12" cy="12" r="3"/><path d="M12 3 V6"/><path d="M12 18 V21"/><path d="M3 12 H6"/><path d="M18 12 H21"/><path d="M5.6 5.6 L7.8 7.8"/><path d="M16.2 16.2 L18.4 18.4"/><path d="M18.4 5.6 L16.2 7.8"/><path d="M7.8 16.2 L5.6 18.4"/></svg>`
