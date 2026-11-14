package ui

import (
	"errors"
	"testing"
)

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

func TestManualBackupUsesChosenPathAndReportsCompletion(t *testing.T) {
	m := DemoModel()
	m.Dialogs.Backup = true
	var callback func(error)
	var chosen string
	m.Hooks.BrowseBackup = func() (string, error) { return `C:\Backup\snapshot.zip`, nil }
	m.Hooks.CreateBackupAsync = func(path string, done func(error)) error { chosen, callback = path, done; return nil }
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("backup-create"); err != nil {
		t.Fatal(err)
	}
	if chosen != `C:\Backup\snapshot.zip` || callback == nil || !m.BackupBusy {
		t.Fatal("manual backup did not start with the selected destination")
	}
	secondDialog := false
	m.Hooks.BrowseRestore = func() (string, string, error) { secondDialog = true; return "", "", nil }
	m.Hooks.RestoreBackupAsync = func(string, string, func(error)) error { return nil }
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	_ = tt.Click("backup-restore")
	if secondDialog {
		t.Fatal("restore remained clickable while backup was running")
	}
	callback(errors.New("test failure"))
	if m.BackupBusy || m.Notice != "备份失败: test failure" {
		t.Fatal("backup failure was not shown")
	}
}

func TestManualRestoreUsesNewDirectoryAndAllowsCopy(t *testing.T) {
	m := DemoModel()
	m.Dialogs.Backup = true
	var callback func(error)
	var archive, destination, copied string
	m.Hooks.BrowseRestore = func() (string, string, error) { return `C:\Backup\snapshot.zip`, `C:\Restore\new`, nil }
	m.Hooks.RestoreBackupAsync = func(src, dst string, done func(error)) error {
		archive, destination, callback = src, dst, done
		return nil
	}
	m.Hooks.Copy = func(value string) error { copied = value; return nil }
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("backup-restore"); err != nil {
		t.Fatal(err)
	}
	if archive == "" || destination == "" || callback == nil || !m.BackupBusy {
		t.Fatal("restore did not start")
	}
	callback(nil)
	if m.BackupBusy || m.RestorePath != destination {
		t.Fatal("restore completion was not recorded")
	}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("backup-copy-restore"); err != nil {
		t.Fatal(err)
	}
	if copied != destination {
		t.Fatal("restore directory was not copied")
	}
}

func TestBackupActionsFitMinimumWindowHeight(t *testing.T) {
	m := DemoModel()
	m.Dialogs.Backup = true
	m.RestorePath = `C:\Restore\new`
	tt := renderModel(m, WindowWidth, WindowMinHeight, false)
	for _, id := range []string{"backup-create", "backup-restore", "backup-copy-restore", "webdav-open", "close-备份设置"} {
		element, ok := tt.Find(id)
		if !ok || element.Y < 0 || element.Y+element.H > WindowMinHeight {
			t.Fatalf("backup action %s is outside the minimum window: %+v", id, element)
		}
	}
}
