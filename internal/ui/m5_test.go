package ui

import (
	"errors"
	"testing"
)

func TestSettingsIconsSitOnTheirRows(t *testing.T) {
	m := DemoModel()
	m.Home.TUNAvailable = false
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, 1600, false)
	tun, okTun := tt.Find("tun-row")
	warn, okWarn := tt.Find("tun-warn")
	gear, okGear := tt.Find("tun-gear")
	if !okTun || !okWarn || !okGear || warn.X >= tun.X || gear.X >= tun.X || !overlapsY(warn.Y, warn.H, tun.Y, tun.H) || !overlapsY(gear.Y, gear.H, tun.Y, tun.H) {
		t.Fatalf("tun row %v warn %v gear %v", tun, warn, gear)
	}
	help, okHelp := tt.Find("help-backup")
	backup, okBackup := tt.Find("backup")
	if !okHelp || !okBackup || help.X <= backup.X || !overlapsY(help.Y, help.H, backup.Y, backup.H) {
		t.Fatalf("backup help %v row %v", help, backup)
	}
	coreGear, okCore := tt.Find("core-gear")
	coreRow, okCoreRow := tt.Find("core-row")
	if !okCore || !okCoreRow || coreGear.X <= coreRow.X || !overlapsY(coreGear.Y, coreGear.H, coreRow.Y, coreRow.H) {
		t.Fatalf("core gear %v row %v", coreGear, coreRow)
	}
}

func TestTunStackDefaultsToSubscription(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, 1600, false)
	if err := tt.Click("tun-gear"); err != nil {
		t.Fatal(err)
	}
	if m.TunStack != "跟随订阅" || !tt.HasText("跟随订阅") {
		t.Fatalf("stack %q texts %q", m.TunStack, tt.Texts())
	}
}

func TestTunStackChoiceAppliesAndRollsBack(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	var name, value string
	m.Hooks.SetKernelOption = func(n string, v any) error { name = n; value = v.(string); return nil }
	tt := renderModel(m, WindowWidth, 1600, false)
	if err := tt.Click("tun-gear"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("tun-stack"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("System"); err != nil {
		t.Fatal(err)
	}
	if name != "tun-stack" || value != "system" || m.TunStack != "System" {
		t.Fatalf("stack %q option %q=%q", m.TunStack, name, value)
	}
	m.Hooks.SetKernelOption = func(string, any) error { return errors.New("failed") }
	if err := tt.Click("tun-stack"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("Mips"); err != nil {
		t.Fatal(err)
	}
	if m.TunStack != "System" || m.Notice != "failed" {
		t.Fatalf("failed change stack=%q notice=%q", m.TunStack, m.Notice)
	}
}
