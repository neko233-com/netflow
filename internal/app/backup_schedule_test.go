package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/backup"
)

func TestScheduledBackupRequiresExplicitOptInAndExcludesSchedule(t *testing.T) {
	base := t.TempDir()
	dir, dest := filepath.Join(base, "config"), filepath.Join(base, "backups")
	for _, path := range []string{dir, dest} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"test":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	d := newSerialDispatcher()
	a := &App{dir: dir, core: diagnosticsTestEngine{}, dispatch: d.call}
	defer func() { d.close(); a.stopBackup() }()
	if got, err := a.loadBackupSchedule(); err != nil || got.Enabled {
		t.Fatal("automatic backup enabled without explicit opt-in", err)
	}
	if _, err := a.setBackupSchedule(true, dir, 24, time.Now()); err == nil {
		t.Fatal("accepted configuration directory")
	}
	if _, err := a.setBackupSchedule(true, dest, 0, time.Now()); err == nil {
		t.Fatal("accepted invalid interval")
	}
	s, err := a.setBackupSchedule(true, dest, 1, time.Now().Add(-2*time.Hour))
	if err != nil || !s.Enabled {
		t.Fatal("could not enable schedule", err)
	}
	d.call(func() { a.autoBackupOne(time.Now()) })
	deadline := time.Now().Add(15 * time.Second)
	for {
		var busy bool
		d.call(func() { busy = a.backupBusy })
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic backup timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one archive: %v %v", entries, err)
	}
	updated, err := a.loadBackupSchedule()
	if err != nil || !updated.NextRun.After(time.Now()) {
		t.Fatalf("next run not advanced: %+v %v", updated, err)
	}
	restored := filepath.Join(base, "restored")
	if _, err := backup.RestoreContext(context.Background(), filepath.Join(dest, entries[0].Name()), restored); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(restored, scheduleFile)); !os.IsNotExist(err) {
		t.Fatal("restored schedule could resume automatic writes")
	}
	if _, err := a.setBackupSchedule(false, "", 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := a.loadBackupSchedule(); err != nil || got.Enabled {
		t.Fatal("schedule did not disable", err)
	}
}

func TestAutomaticBackupLimitNeverDeletesFiles(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scheduledDestination(ctx, filepath.Join(dir, "missing"), time.Now()); err != context.Canceled {
		t.Fatalf("canceled backup accessed destination: %v", err)
	}
	for i := 0; i < scheduleLimit; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("netflow-auto-%02d.zip", i)), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scheduledDestination(context.Background(), dir, time.Now()); err == nil {
		t.Fatal("accepted an over-capacity destination")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != scheduleLimit {
		t.Fatal("existing archives changed", err)
	}
}

func TestBackupScheduleChecksAreThrottledAndReconfigurationWakesThem(t *testing.T) {
	dir, dest := t.TempDir(), t.TempDir()
	a := &App{dir: dir, core: diagnosticsTestEngine{}}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.autoBackupOne(now)
	if !a.backupCheckAfter.Equal(now.Add(time.Minute)) {
		t.Fatal("disabled schedule did not throttle disk reads")
	}
	if err := os.WriteFile(filepath.Join(dir, scheduleFile), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	a.autoBackupOne(now.Add(5 * time.Second))
	if a.backupScheduleError != "" {
		t.Fatal("read schedule before the throttle elapsed")
	}
	a.autoBackupOne(now.Add(time.Minute))
	if a.backupScheduleError == "" {
		t.Fatal("failed to recheck an externally changed schedule")
	}
	if _, err := a.setBackupSchedule(true, dest, 24, now); err != nil {
		t.Fatal(err)
	}
	if !a.backupCheckAfter.IsZero() || !a.backupRetry.IsZero() {
		t.Fatal("explicit reconfiguration did not wake the scheduler")
	}
	a.autoBackupOne(now.Add(5 * time.Second))
	if !a.backupCheckAfter.Equal(now.Add(65 * time.Second)) {
		t.Fatal("future schedule was not throttled")
	}
}

func TestBackupOnChangeBaselineAndContentChanges(t *testing.T) {
	base := t.TempDir()
	dir, dest := filepath.Join(base, "config"), filepath.Join(base, "backups")
	for _, path := range []string{dir, dest} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	d := newSerialDispatcher()
	a := &App{dir: dir, core: diagnosticsTestEngine{}, dispatch: d.call}
	defer func() { d.close(); a.stopBackup() }()
	var err error
	d.call(func() { _, err = a.setBackupOnChange(true) })
	if err == nil {
		t.Fatal("change backups enabled without directory consent")
	}
	d.call(func() { _, err = a.setBackupSchedule(true, dest, 24, time.Now()) })
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.loadBackupSchedule()
	if err != nil || s.OnChange {
		t.Fatal("change backups enabled implicitly", err)
	}
	d.call(func() { _, err = a.setBackupOnChange(true); a.autoBackupOne(time.Now()) })
	if err != nil {
		t.Fatal(err)
	}
	wait := func() {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			var busy bool
			d.call(func() { busy = a.backupBusy || a.backupScanBusy })
			if !busy {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("automatic work timed out")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait()
	state, _, err := a.readBackupSchedule()
	if err != nil || state.Baseline == "" {
		t.Fatal("baseline not persisted", err)
	}
	files, _ := os.ReadDir(dest)
	if len(files) != 1 {
		t.Fatalf("baseline count %d", len(files))
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	d.call(func() { a.autoBackupOne(time.Now()) })
	wait()
	d.call(func() {
		if a.backupChangeDue.IsZero() {
			t.Error("change was not detected")
		}
		a.backupChangeDue = time.Now().Add(-time.Second)
		a.backupCheckAfter = time.Time{}
		a.autoBackupOne(time.Now())
	})
	wait()
	files, _ = os.ReadDir(dest)
	if len(files) != 2 {
		t.Fatalf("changed snapshot count %d", len(files))
	}
	d.call(func() { a.autoBackupOne(time.Now()) })
	wait()
	d.call(func() {
		if !a.backupChangeDue.IsZero() {
			t.Error("unchanged content caused repeat backup")
		}
		_, err = a.setBackupOnChange(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err = a.loadBackupSchedule()
	if err != nil || s.OnChange {
		t.Fatal("change backups did not disable", err)
	}
}

func TestBackupScheduleCompareRejectsStaleUpdate(t *testing.T) {
	dir, dest := t.TempDir(), t.TempDir()
	a := &App{dir: dir}
	if _, err := a.setBackupSchedule(true, dest, 24, time.Now()); err != nil {
		t.Fatal(err)
	}
	old, raw, err := a.readBackupSchedule()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.setBackupOnChange(true); err != nil {
		t.Fatal(err)
	}
	if err := a.writeBackupState(old, raw); err == nil {
		t.Fatal("stale schedule overwrote user change")
	}
	current, err := a.loadBackupSchedule()
	if err != nil || !current.OnChange {
		t.Fatal("new schedule lost", err)
	}
}
