package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/neko233-com/netflow/internal/ui"
)

type shortcutRegistrar interface {
	Register(string, func()) error
	Unregister(string)
}
type hotkeyBinding struct{ accelerator, action string }

func (a *App) applyHotkeys(p ui.Prefs) error { return a.configureHotkeys(p, true) }

// Register additions first. A conflict or persistence failure removes only
// those additions and leaves the previous shortcuts operational.
func (a *App) configureHotkeys(p ui.Prefs, persist bool) error {
	if a.shortcuts == nil {
		return errors.New("快捷键服务不可用")
	}
	entries := []hotkeyBinding{{p.HotkeyDash, "dashboard"}, {p.HotkeyRule, "rule"}, {p.HotkeyGlobal, "global"}, {p.HotkeyDirect, "direct"}, {p.HotkeyTUN, "tun"}, {p.HotkeyLite, "lite"}, {p.HotkeyProfiles, "profile"}}
	desired := make(map[string]hotkeyBinding)
	var ordered []string
	for _, entry := range entries {
		entry.accelerator = strings.TrimSpace(entry.accelerator)
		if entry.accelerator == "" {
			continue
		}
		key := strings.ToLower(entry.accelerator)
		if _, exists := desired[key]; exists {
			return fmt.Errorf("快捷键重复: %s", entry.accelerator)
		}
		desired[key] = entry
		ordered = append(ordered, key)
	}
	var added []string
	rollback := func() {
		for _, key := range added {
			a.shortcuts.Unregister(desired[key].accelerator)
		}
	}
	for _, key := range ordered {
		if _, exists := a.hotkeys[key]; exists {
			continue
		}
		binding := desired[key]
		captured := key
		if err := a.shortcuts.Register(binding.accelerator, func() { a.invokeHotkey(captured) }); err != nil {
			rollback()
			return fmt.Errorf("注册 %s 失败: %w", binding.accelerator, err)
		}
		added = append(added, key)
	}
	if persist {
		next := a.model.Prefs
		next.HotkeyDash = p.HotkeyDash
		next.HotkeyRule = p.HotkeyRule
		next.HotkeyGlobal = p.HotkeyGlobal
		next.HotkeyDirect = p.HotkeyDirect
		next.HotkeyProxy = p.HotkeyProxy
		next.HotkeyTUN = p.HotkeyTUN
		next.HotkeyLite = p.HotkeyLite
		next.HotkeyProfiles = p.HotkeyProfiles
		if err := a.savePrefs(next); err != nil {
			rollback()
			return err
		}
		a.model.Prefs = next
	}
	for key, old := range a.hotkeys {
		if _, keep := desired[key]; !keep {
			a.shortcuts.Unregister(old.accelerator)
		}
	}
	a.hotkeys = desired
	return nil
}

func (a *App) releaseHotkeys() {
	if a.shortcuts != nil {
		for _, binding := range a.hotkeys {
			a.shortcuts.Unregister(binding.accelerator)
		}
	}
	a.hotkeys = nil
}

func (a *App) invokeHotkey(key string) {
	if a.model == nil {
		return
	}
	binding, ok := a.hotkeys[key]
	if !ok {
		return
	}
	var err error
	switch binding.action {
	case "dashboard":
		a.showMain()
	case "rule", "global", "direct":
		err = a.SetMode(binding.action)
	case "tun":
		err = a.SetTUN(!a.settings.TUN)
	case "lite":
		err = a.setLightweight(!a.model.Prefs.Lightweight)
	case "profile":
		if a.model.CurrentProfile == "" {
			err = errors.New("没有已激活的订阅")
		} else {
			err = a.UseProfile(a.model.CurrentProfile)
		}
	}
	if err != nil {
		a.model.Notice = err.Error()
	} else {
		a.model.Notice = "快捷键操作已完成"
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}
