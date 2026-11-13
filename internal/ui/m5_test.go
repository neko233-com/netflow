package ui

import (
	"errors"
	"testing"
)

func TestServiceModeDialog(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	installed := 0
	uninstalled := 0
	m.Hooks.InstallService = func() error {
		installed++
		return nil
	}
	m.Hooks.UninstallService = func() error {
		uninstalled++
		return nil
	}
	tt := renderModel(m, WindowWidth, 1600, false)
	if !tt.HasText("服务模式") || !tt.HasText("未安装") {
		t.Fatalf("row texts %q", tt.Texts())
	}
	if err := tt.Click("service-row"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("安装服务") || !tt.HasText("当前状态：未安装") {
		t.Fatalf("dialog texts %q", tt.Texts())
	}
	if err := tt.Click("service-install"); err != nil {
		t.Fatal(err)
	}
	if installed != 1 || !m.ServiceInstalled || !m.Home.TUNAvailable || m.Notice != "已成功安装服务" {
		t.Fatalf("install n %d installed %v tun %v notice %q", installed, m.ServiceInstalled, m.Home.TUNAvailable, m.Notice)
	}
	if !tt.HasText("已安装") || !tt.HasText("卸载服务") {
		t.Fatalf("after install %q", tt.Texts())
	}
	if err := tt.Click("service-uninstall"); err != nil {
		t.Fatal(err)
	}
	if uninstalled != 1 || m.ServiceInstalled || m.Notice != "已成功卸载服务" {
		t.Fatalf("uninstall n %d installed %v notice %q", uninstalled, m.ServiceInstalled, m.Notice)
	}

	m.Hooks.InstallService = func() error { return errors.New("denied") }
	if err := tt.Click("service-install"); err != nil {
		t.Fatal(err)
	}
	if m.ServiceInstalled || m.Notice != "安装服务失败" {
		t.Fatalf("failed install installed %v notice %q", m.ServiceInstalled, m.Notice)
	}
}

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

func TestTunStackDefaultsToMips(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/settings")
	tt := renderModel(m, WindowWidth, 1600, false)
	if err := tt.Click("tun-gear"); err != nil {
		t.Fatal(err)
	}
	if m.TunStack != "Mips" || !tt.HasText("Mips") {
		t.Fatalf("stack %q texts %q", m.TunStack, tt.Texts())
	}
}
