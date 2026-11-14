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
