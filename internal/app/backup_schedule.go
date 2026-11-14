package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/safepath"
)

const scheduleFile = "backup-schedule.json"
const scheduleLimit = 30

// Schedule configuration is deliberately excluded from backups: restoring a
// snapshot must never silently resume writing to the original destination.
func (a *App) loadBackupSchedule() (agent.BackupSchedule, error) {
	data, err := safepath.ReadFileLimit(a.dir, scheduleFile, 32<<10)
	if errors.Is(err, os.ErrNotExist) {
		return agent.BackupSchedule{}, nil
	}
	if err != nil {
		return agent.BackupSchedule{}, err
	}
	var s agent.BackupSchedule
	if err := json.Unmarshal(data, &s); err != nil {
		return agent.BackupSchedule{}, errors.New("invalid backup schedule")
	}
	if s.Enabled && (!validArchivePath(s.Directory) || s.IntervalHours < 1 || s.IntervalHours > 168 || s.NextRun.IsZero()) {
		return agent.BackupSchedule{}, errors.New("invalid backup schedule")
	}
	return s, nil
}

func (a *App) saveBackupSchedule(s agent.BackupSchedule) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return safepath.WriteFile(a.dir, scheduleFile, data)
}

func (a *App) setBackupSchedule(enabled bool, directory string, hours int, now time.Time) (agent.BackupSchedule, error) {
	if !enabled {
		s := agent.BackupSchedule{}
		if err := a.saveBackupSchedule(s); err != nil {
			return s, err
		}
		if a.model != nil {
			a.model.BackupSchedule = s
		}
		a.backupRetry, a.backupCheckAfter, a.backupScheduleError = time.Time{}, time.Time{}, ""
		return s, nil
	}
	if !validArchivePath(directory) || hours < 1 || hours > 168 {
		return agent.BackupSchedule{}, errors.New("schedule requires an absolute directory and an interval of 1 to 168 hours")
	}
	config, err := safepath.Canonical(a.dir)
	if err != nil {
		return agent.BackupSchedule{}, errors.New("configuration directory is unavailable")
	}
	directory, err = safepath.Canonical(directory)
	if err != nil {
		return agent.BackupSchedule{}, errors.New("backup directory is unavailable")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return agent.BackupSchedule{}, errors.New("backup destination is not a directory")
	}
	rel, err := filepath.Rel(config, directory)
	if err == nil && (rel == "." || (filepath.IsLocal(rel) && rel != "..")) {
		return agent.BackupSchedule{}, errors.New("backup directory must be outside the configuration")
	}
	s := agent.BackupSchedule{Enabled: true, Directory: directory, IntervalHours: hours, NextRun: now.UTC().Add(time.Duration(hours) * time.Hour)}
	if err := a.saveBackupSchedule(s); err != nil {
		return agent.BackupSchedule{}, err
	}
	if a.model != nil {
		a.model.BackupSchedule = s
		a.model.BackupHours = fmt.Sprint(hours)
	}
	a.backupRetry, a.backupCheckAfter, a.backupScheduleError = time.Time{}, time.Time{}, ""
	return s, nil
}

// Scheduled archives are never deleted automatically. A bounded number of
// app-named files prevents unattended growth until the user clears space.
func scheduledDestination(ctx context.Context, directory string, now time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	defer f.Close()
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		entries, e := f.Readdirnames(128)
		for _, name := range entries {
			if strings.HasPrefix(name, "netflow-auto-") && strings.HasSuffix(name, ".zip") {
				count++
				if count >= scheduleLimit {
					return "", errors.New("automatic backup limit reached; remove old archives manually")
				}
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return filepath.Join(directory, "netflow-auto-"+now.UTC().Format("20060102-150405")+"-"+hex.EncodeToString(nonce[:])+".zip"), nil
}

func (a *App) autoBackupOne(now time.Time) {
	if a.backupBusy || a.tunBusy || now.Before(a.backupRetry) || now.Before(a.backupCheckAfter) {
		return
	}
	s, err := a.loadBackupSchedule()
	if err != nil {
		a.backupRetry, a.backupScheduleError = now.Add(autoRetryDelay), "cannot read automatic backup schedule"
		return
	}
	if !s.Enabled {
		a.backupCheckAfter = now.Add(time.Minute)
		return
	}
	if now.Before(s.NextRun) {
		a.backupCheckAfter = s.NextRun
		if limit := now.Add(time.Minute); a.backupCheckAfter.After(limit) {
			a.backupCheckAfter = limit
		}
		return
	}
	dir := a.dir
	_, err = a.beginArchiveJob("scheduled", now, func(jobErr error) {
		current, loadErr := a.loadBackupSchedule()
		if loadErr != nil || current != s {
			return // The user changed or disabled this schedule in the meantime.
		}
		if jobErr == nil {
			current.NextRun = time.Now().UTC().Add(time.Duration(current.IntervalHours) * time.Hour)
			jobErr = a.saveBackupSchedule(current)
		}
		if jobErr != nil {
			a.backupRetry = time.Now().Add(autoRetryDelay)
			a.backupScheduleError = "automatic backup failed; check destination, archive limit and configuration activity"
			if a.model != nil {
				a.model.Notice = "自动备份失败；检查目录、备份数量和配置变动，15 分钟后重试"
			}
		} else {
			a.backupScheduleError = ""
			if a.model != nil {
				a.model.Notice = "自动备份已创建"
			}
		}
	}, func(ctx context.Context) error {
		path, err := scheduledDestination(ctx, s.Directory, now)
		if err != nil {
			return err
		}
		_, err = backup.ExportRunning(ctx, dir, path)
		return err
	})
	if err != nil {
		a.backupRetry = now.Add(autoRetryDelay)
		a.backupScheduleError = "automatic backup unavailable; check directory and archive limit"
		if a.model != nil {
			a.model.Notice = "自动备份失败；检查目标目录和备份数量"
		}
	}
}
