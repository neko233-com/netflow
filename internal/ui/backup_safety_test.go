package ui

import (
	"errors"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestUnsupportedBackupDoesNotExposeSavedPassword(t *testing.T) {
	m := DemoModel()
	m.Prefs.WebDAVPassword = "synthetic-never-display"
	m.Prefs.WebDAVURL = "https://synthetic-url-secret@backup.invalid"
	m.Prefs.WebDAVUser = "synthetic-hidden-user"
	m.WebDAVSecretStored = true
	m.Dialogs.Backup = true
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("备份包含敏感信息且未加密") || tt.HasText("synthetic-never-display") {
		t.Fatal("backup status or password visibility is incorrect")
	}
	if m.BackupSchedule.Enabled {
		t.Fatal("automatic backup enabled by default")
	}
	m.Dialogs.Backup = false
	m.Dialogs.WebDAV = true
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if !tt.HasText("上传会发送所选未加密备份") || tt.HasText("synthetic-never-display") || tt.HasText("synthetic-url-secret") || tt.HasText("synthetic-hidden-user") {
		t.Fatal("WebDAV status or password visibility is incorrect")
	}
}

func TestAutomaticBackupRequiresChoosingDirectory(t *testing.T) {
	m := DemoModel()
	m.Dialogs.Backup = true
	called := false
	m.Hooks.BrowseBackupDirectory = func() (string, error) { return "", nil }
	m.Hooks.SetBackupSchedule = func(enabled bool, directory string, hours int) (agent.BackupSchedule, error) {
		called = true
		return agent.BackupSchedule{Enabled: enabled, Directory: directory, IntervalHours: hours}, nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("backup-auto-enable"); err != nil {
		t.Fatal(err)
	}
	if called || m.BackupSchedule.Enabled {
		t.Fatal("canceling directory selection enabled backups")
	}
	m.Hooks.BrowseBackupDirectory = func() (string, error) { return `C:\Backups`, nil }
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("backup-auto-enable"); err != nil {
		t.Fatal(err)
	}
	if !called || !m.BackupSchedule.Enabled || m.BackupSchedule.IntervalHours != 24 {
		t.Fatal("explicit opt-in was not saved")
	}
}

func TestWebDAVUploadNeedsExplicitSelectionAndDoesNotDisplayPassword(t *testing.T) {
	m := DemoModel()
	m.Dialogs.WebDAV = true
	m.WebDAVURLDraft, m.WebDAVUserDraft, m.WebDAVPasswordDraft = "https://backup.invalid/dav", "user", "synthetic-password"
	called := false
	m.Hooks.BrowseWebDAVArchive = func() (string, error) { return "", nil }
	m.Hooks.UploadWebDAVAsync = func(args agent.WebDAVUploadArgs, done func(string, error)) error {
		called = true
		if args.Archive == "" || args.Password != "synthetic-password" {
			t.Error("upload arguments were lost")
		}
		done("netflow-test.zip", nil)
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if tt.HasText("synthetic-password") {
		t.Fatal("password was visible")
	}
	if err := tt.Click("webdav-upload"); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("canceling selection started upload")
	}
	m.Hooks.BrowseWebDAVArchive = func() (string, error) { return `C:\Backups\test.zip`, nil }
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("webdav-upload"); err != nil {
		t.Fatal(err)
	}
	if !called || m.WebDAVPasswordDraft != "" || m.Notice != "WebDAV 备份已上传: netflow-test.zip" {
		t.Fatal("upload completion or password clearing failed")
	}
}

func TestWebDAVActionsFitMinimumWindowHeight(t *testing.T) {
	m := DemoModel()
	m.Dialogs.WebDAV, m.WebDAVSecretStored = true, true
	tt := renderModel(m, WindowWidth, WindowMinHeight, false)
	for _, id := range []string{"webdav-upload", "webdav-upload-saved", "webdav-list", "webdav-list-saved", "webdav-save", "webdav-restore", "webdav-restore-saved", "webdav-clear-secret", "webdav-clear", "close-WebDAV"} {
		element, ok := tt.Find(id)
		if !ok || element.Y < 0 || element.Y+element.H > WindowMinHeight {
			t.Fatalf("WebDAV action %s is outside the minimum window: %+v", id, element)
		}
	}
}

func TestWebDAVSaveAndClearRequireExplicitActions(t *testing.T) {
	m := DemoModel()
	m.Dialogs.WebDAV = true
	m.WebDAVURLDraft, m.WebDAVUserDraft, m.WebDAVPasswordDraft = "https://backup.invalid/dav", "user", "synthetic-password"
	saved, cleared := false, false
	m.Hooks.SaveWebDAVConfig = func(args agent.WebDAVConfigArgs) error {
		saved = true
		if args.Password != "synthetic-password" {
			t.Error("password was not passed to protected storage")
		}
		return nil
	}
	m.Hooks.ClearWebDAVConfig = func() error { cleared = true; return nil }
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if saved || cleared {
		t.Fatal("configuration changed without explicit action")
	}
	if err := tt.Click("webdav-save"); err != nil {
		t.Fatal(err)
	}
	if !saved || !m.WebDAVSecretStored || m.WebDAVPasswordDraft != "" || m.WebDAVURLDraft != "" {
		t.Fatal("save did not clear drafts")
	}
	tt = renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("webdav-clear"); err != nil {
		t.Fatal(err)
	}
	if !cleared || m.WebDAVSecretStored {
		t.Fatal("clear did not remove stored configuration state")
	}
}

func TestWebDAVListSelectsBackupWithoutPersistingCredentials(t *testing.T) {
	m := DemoModel()
	m.Dialogs.WebDAV = true
	m.WebDAVURLDraft, m.WebDAVUserDraft, m.WebDAVPasswordDraft = "https://backup.invalid/dav", "user", "synthetic-password"
	name := "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"
	m.Hooks.ListWebDAVAsync = func(args agent.WebDAVListArgs, done func([]string, error)) error {
		if args.Password != "synthetic-password" || args.UseSaved {
			t.Error("listing arguments lost")
		}
		done([]string{name}, nil)
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("webdav-list"); err != nil {
		t.Fatal(err)
	}
	if m.WebDAVRemoteDraft != name || len(m.WebDAVRemoteNames) != 1 || m.BackupBusy {
		t.Fatal("listing was not available for restore")
	}
	m.Dialogs.WebDAV = false
	_ = renderModel(m, WindowWidth, WindowHeight, false)
	if m.WebDAVPasswordDraft != "" || m.WebDAVURLDraft != "" {
		t.Fatal("closing dialog retained credentials")
	}
}

func TestWebDAVRestoreSelectsNewDestinationAndClearsPassword(t *testing.T) {
	m := DemoModel()
	m.Dialogs.WebDAV = true
	m.WebDAVURLDraft, m.WebDAVPasswordDraft = "https://backup.invalid/dav", "synthetic-password"
	m.WebDAVRemoteDraft = "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"
	m.RestorePath = `C:\Restore\old`
	m.Hooks.BrowseRestoreDestination = func() (string, error) { return `C:\Restore\new`, nil }
	called := false
	var callback func(error)
	m.Hooks.RestoreWebDAVAsync = func(args agent.WebDAVRestoreArgs, done func(error)) error {
		called = true
		if args.Destination != `C:\Restore\new` || args.Password != "synthetic-password" {
			t.Error("restore arguments lost")
		}
		callback = done
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("webdav-restore"); err != nil {
		t.Fatal(err)
	}
	if callback == nil || m.RestorePath != "" {
		t.Fatal("old destination remained visible during restore")
	}
	callback(nil)
	if !called || m.WebDAVPasswordDraft != "" || m.RestorePath != `C:\Restore\new` {
		t.Fatal("restore did not finish correctly")
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
	m.BackupSchedule = agent.BackupSchedule{Enabled: true, Directory: `C:\Backups`, IntervalHours: 24}
	m.RestorePath = `C:\Restore\new`
	tt := renderModel(m, WindowWidth, WindowMinHeight, false)
	for _, id := range []string{"backup-create", "backup-restore", "backup-copy-restore", "webdav-open", "close-备份设置"} {
		element, ok := tt.Find(id)
		if !ok || element.Y < 0 || element.Y+element.H > WindowMinHeight {
			t.Fatalf("backup action %s is outside the minimum window: %+v", id, element)
		}
	}
}

func TestChangeBackupRequiresExplicitToggle(t *testing.T) {
	m := DemoModel()
	m.Dialogs.Backup = true
	m.BackupSchedule = agent.BackupSchedule{Enabled: true, Directory: `C:\Backups`, IntervalHours: 24}
	called := false
	m.Hooks.SetBackupOnChange = func(on bool) (agent.BackupSchedule, error) {
		called = on
		s := m.BackupSchedule
		s.OnChange = on
		return s, nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if called || m.BackupSchedule.OnChange {
		t.Fatal("change backup enabled implicitly")
	}
	if err := tt.Click("backup-on-change"); err != nil {
		t.Fatal(err)
	}
	if !called || !m.BackupSchedule.OnChange {
		t.Fatal("explicit change backup toggle did not apply")
	}
}
