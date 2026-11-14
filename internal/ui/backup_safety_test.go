package ui

import "testing"

func TestUnsupportedBackupDoesNotExposeSavedPassword(t *testing.T) {
	m := DemoModel()
	m.Prefs.WebDAVPassword = "synthetic-never-display"
	m.Prefs.WebDAVURL = "https://synthetic-url-secret@backup.invalid"
	m.Prefs.WebDAVUser = "synthetic-hidden-user"
	m.WebDAVSecretStored = true
	m.Dialogs.Backup = true
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("备份尚未实现") || tt.HasText("synthetic-never-display") {
		t.Fatal("backup status or password visibility is incorrect")
	}
	before := m.Prefs.AutoBackup
	_ = tt.Click("backup-auto-disabled")
	if m.Prefs.AutoBackup != before {
		t.Fatal("unsupported backup switch changed")
	}
	m.Dialogs.Backup = false
	m.Dialogs.WebDAV = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("WebDAV 备份尚未实现") || tt.HasText("synthetic-never-display") || tt.HasText("synthetic-url-secret") || tt.HasText("synthetic-hidden-user") {
		t.Fatal("WebDAV status or password visibility is incorrect")
	}
}
