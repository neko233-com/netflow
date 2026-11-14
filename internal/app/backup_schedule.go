package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
type queuedWebDAVBackup struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type backupScheduleState struct {
	agent.BackupSchedule
	Baseline      string               `json:"baseline,omitempty"`
	WebDAVBinding string               `json:"webdav_binding,omitempty"`
	WebDAVQueue   []queuedWebDAVBackup `json:"webdav_queue,omitempty"`
}

func (a *App) readBackupSchedule() (backupScheduleState, []byte, error) {
	data, err := safepath.ReadFileLimit(a.dir, scheduleFile, 32<<10)
	if errors.Is(err, os.ErrNotExist) {
		return backupScheduleState{}, nil, nil
	}
	if err != nil {
		return backupScheduleState{}, nil, err
	}
	var state backupScheduleState
	if err := json.Unmarshal(data, &state); err != nil {
		return backupScheduleState{}, nil, errors.New("invalid backup schedule")
	}
	s := state.BackupSchedule
	if s.Enabled && (!validArchivePath(s.Directory) || s.IntervalHours < 1 || s.IntervalHours > 168 || s.NextRun.IsZero()) {
		return backupScheduleState{}, nil, errors.New("invalid backup schedule")
	}
	if state.Baseline != "" {
		digest, err := hex.DecodeString(state.Baseline)
		if err != nil || len(digest) != 32 {
			return backupScheduleState{}, nil, errors.New("invalid backup baseline")
		}
	}
	validDigest := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == sha256.Size
	}
	if len(state.WebDAVQueue) > scheduleLimit || (state.WebDAV && (!state.Enabled || !validDigest(state.WebDAVBinding))) || (!state.WebDAV && (state.WebDAVBinding != "" || len(state.WebDAVQueue) != 0)) {
		return backupScheduleState{}, nil, errors.New("invalid WebDAV backup schedule")
	}
	for _, item := range state.WebDAVQueue {
		if filepath.Base(item.Name) != item.Name || !strings.HasPrefix(item.Name, "netflow-auto-") || !strings.HasSuffix(item.Name, ".zip") || !validDigest(item.Digest) {
			return backupScheduleState{}, nil, errors.New("invalid queued backup")
		}
	}
	state.WebDAVPending, state.WebDAVError, state.WebDAVRetry = len(state.WebDAVQueue), "", time.Time{}
	return state, data, nil
}
func (a *App) loadBackupSchedule() (agent.BackupSchedule, error) {
	state, _, err := a.readBackupSchedule()
	return state.BackupSchedule, err
}
func (a *App) writeBackupState(state backupScheduleState, expected []byte) error {
	state.WebDAVPending, state.WebDAVError, state.WebDAVRetry = len(state.WebDAVQueue), "", time.Time{}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return safepath.CompareAndWrite(a.dir, scheduleFile, expected, data)
}
func (a *App) resetBackupMonitor() {
	if a.backupScanCancel != nil {
		a.backupScanCancel()
	}
	a.backupInventory, a.backupReconcile, a.backupChangeDue = "", time.Time{}, time.Time{}
	a.backupRetry, a.backupCheckAfter, a.backupScheduleError = time.Time{}, time.Time{}, ""
}

// Binding is to the saved protected blob, not to plaintext credentials. A
// changed settings file or credential replacement stops unattended transfers.
func (a *App) webDAVScheduleBinding() (string, error) {
	if a.store == nil {
		return "", errors.New("protected WebDAV settings unavailable")
	}
	if checker, ok := a.store.(interface{ CheckCurrent() error }); ok {
		if err := checker.CheckCurrent(); err != nil {
			return "", errors.New("WebDAV settings changed outside NetFlow")
		}
	}
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return "", errors.New("protected WebDAV settings unavailable")
	}
	protected, err := prefString(data, webDAVProtectedKey)
	if err != nil || protected == "" {
		return "", errors.New("save account-protected WebDAV credentials first")
	}
	if _, err := a.webDAVCredentials("", "", "", true); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(protected))
	return hex.EncodeToString(digest[:]), nil
}
func (a *App) setBackupWebDAV(enabled bool) (agent.BackupSchedule, error) {
	state, raw, err := a.readBackupSchedule()
	if err != nil {
		return agent.BackupSchedule{}, err
	}
	if !state.Enabled {
		return agent.BackupSchedule{}, errors.New("enable a local backup schedule first")
	}
	if state.WebDAV == enabled {
		return state.BackupSchedule, nil
	}
	if enabled {
		state.WebDAVBinding, err = a.webDAVScheduleBinding()
		if err != nil {
			return agent.BackupSchedule{}, err
		}
	} else {
		state.WebDAVBinding = ""
		state.WebDAVQueue = nil
	}
	state.WebDAV = enabled
	if err := a.writeBackupState(state, raw); err != nil {
		return agent.BackupSchedule{}, err
	}
	if !enabled && a.backupAutoJob && a.backupCancel != nil {
		a.backupCancel()
	}
	a.backupWebDAVRetry, a.backupWebDAVError = time.Time{}, ""
	a.resetBackupMonitor()
	state.WebDAVPending = len(state.WebDAVQueue)
	if a.model != nil {
		a.model.BackupSchedule = state.BackupSchedule
	}
	return state.BackupSchedule, nil
}

func (a *App) setBackupOnChange(enabled bool) (agent.BackupSchedule, error) {
	state, raw, err := a.readBackupSchedule()
	if err != nil {
		return agent.BackupSchedule{}, err
	}
	if !state.Enabled {
		return agent.BackupSchedule{}, errors.New("enable a backup schedule first")
	}
	if state.OnChange == enabled {
		return state.BackupSchedule, nil
	}
	state.OnChange, state.Baseline = enabled, ""
	if err := a.writeBackupState(state, raw); err != nil {
		return agent.BackupSchedule{}, err
	}
	if !enabled && a.backupAutoJob && a.backupCancel != nil {
		a.backupCancel()
	}
	a.resetBackupMonitor()
	if a.model != nil {
		a.model.BackupSchedule = state.BackupSchedule
	}
	return state.BackupSchedule, nil
}

func (a *App) setBackupSchedule(enabled bool, directory string, hours int, now time.Time) (agent.BackupSchedule, error) {
	if !enabled {
		s := agent.BackupSchedule{}
		raw, err := safepath.ReadFileLimit(a.dir, scheduleFile, 32<<10)
		if errors.Is(err, os.ErrNotExist) {
			raw, err = nil, nil
		}
		if err != nil {
			return s, err
		}
		if err := a.writeBackupState(backupScheduleState{}, raw); err != nil {
			return s, err
		}
		if a.model != nil {
			a.model.BackupSchedule = s
		}
		if a.backupAutoJob && a.backupCancel != nil {
			a.backupCancel()
		}
		a.backupWebDAVError, a.backupWebDAVRetry = "", time.Time{}
		a.resetBackupMonitor()
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
	old, raw, readErr := a.readBackupSchedule()
	if readErr != nil {
		raw, readErr = safepath.ReadFileLimit(a.dir, scheduleFile, 32<<10)
		if errors.Is(readErr, os.ErrNotExist) {
			raw, readErr = nil, nil
		}
		if readErr != nil {
			return agent.BackupSchedule{}, readErr
		}
	}
	if old.Enabled && old.Directory != directory && len(old.WebDAVQueue) > 0 {
		return agent.BackupSchedule{}, errors.New("disable automatic WebDAV upload before changing the backup directory")
	}
	state := backupScheduleState{BackupSchedule: s}
	if old.Enabled && old.Directory == directory {
		state.OnChange, state.Baseline = old.OnChange, old.Baseline
		state.WebDAV, state.WebDAVBinding, state.WebDAVQueue = old.WebDAV, old.WebDAVBinding, old.WebDAVQueue
		state.WebDAVPending = len(state.WebDAVQueue)
	}
	s = state.BackupSchedule
	if err := a.writeBackupState(state, raw); err != nil {
		return agent.BackupSchedule{}, err
	}
	if a.model != nil {
		a.model.BackupSchedule = s
		a.model.BackupHours = fmt.Sprint(hours)
	}
	if a.backupAutoJob && a.backupCancel != nil {
		a.backupCancel()
	}
	a.resetBackupMonitor()
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

// Inventory is a cheap hint; periodic content reconciliation detects edits
// that preserve file size and timestamps. Both run away from the UI thread.
func (a *App) startBackupScan(state backupScheduleState, raw []byte, now time.Time) {
	if a.backupScanBusy {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	a.backupScanBusy, a.backupScanCancel, a.backupScanDone = true, cancel, finished
	previous, full := a.backupInventory, !now.Before(a.backupReconcile)
	dir := a.dir
	go func() {
		inventory, err := backup.RunningInventory(ctx, dir)
		var fingerprint string
		checked := err == nil && (full || previous == "" || previous != inventory)
		if checked {
			fingerprint, err = backup.RunningFingerprint(ctx, dir)
		}
		canceled := ctx.Err() != nil
		cancel()
		close(finished)
		a.runOnMain(func() {
			a.backupScanBusy, a.backupScanCancel, a.backupScanDone = false, nil, nil
			if canceled {
				return
			}
			current, currentRaw, loadErr := a.readBackupSchedule()
			if loadErr != nil || !bytes.Equal(raw, currentRaw) || !current.Enabled || !current.OnChange {
				return
			}
			if err != nil {
				a.backupScheduleError = "automatic backup scan failed; check configuration activity"
				a.backupRetry = time.Now().Add(autoRetryDelay)
				return
			}
			a.backupInventory = inventory
			if checked {
				a.backupReconcile = time.Now().Add(10 * time.Minute)
				if fingerprint != state.Baseline {
					if a.backupChangeDue.IsZero() {
						a.backupChangeDue = time.Now().Add(10 * time.Second)
					}
					a.backupCheckAfter = a.backupChangeDue
				} else {
					a.backupChangeDue = time.Time{}
				}
			}
		})
	}()
}

func (a *App) autoBackupOne(now time.Time) {
	if a.backupBusy || a.backupScanBusy || a.tunBusy || now.Before(a.backupCheckAfter) {
		return
	}
	state, raw, err := a.readBackupSchedule()
	if err != nil {
		a.backupRetry, a.backupScheduleError = now.Add(autoRetryDelay), "cannot read automatic backup schedule"
		a.backupCheckAfter = a.backupRetry
		return
	}
	s := state.BackupSchedule
	if !s.Enabled {
		a.backupCheckAfter = now.Add(time.Minute)
		return
	}
	due := !now.Before(s.NextRun) || (s.OnChange && (state.Baseline == "" || (!a.backupChangeDue.IsZero() && !now.Before(a.backupChangeDue))))
	// A local scan or archive failure must not block an independent queued
	// upload. Preserve each retry deadline and wake at the earliest one.
	if now.Before(a.backupRetry) {
		if s.WebDAV && len(state.WebDAVQueue) > 0 && !now.Before(a.backupWebDAVRetry) {
			a.startScheduledWebDAV(state, raw, now)
			return
		}
		a.backupCheckAfter = now.Add(time.Minute)
		if a.backupRetry.Before(a.backupCheckAfter) {
			a.backupCheckAfter = a.backupRetry
		}
		if s.WebDAV && len(state.WebDAVQueue) > 0 && now.Before(a.backupWebDAVRetry) && a.backupWebDAVRetry.Before(a.backupCheckAfter) {
			a.backupCheckAfter = a.backupWebDAVRetry
		}
		return
	}
	if !due && s.WebDAV && len(state.WebDAVQueue) > 0 && !now.Before(a.backupWebDAVRetry) {
		a.startScheduledWebDAV(state, raw, now)
		return
	}
	if !due {
		a.backupCheckAfter = s.NextRun
		interval := time.Minute
		if s.OnChange {
			interval = 30 * time.Second
		}
		if limit := now.Add(interval); a.backupCheckAfter.After(limit) {
			a.backupCheckAfter = limit
		}
		if s.OnChange {
			a.startBackupScan(state, raw, now)
		}
		return
	}
	if s.WebDAV && len(state.WebDAVQueue) >= scheduleLimit {
		a.backupScheduleError = "automatic backup waiting; WebDAV upload queue is full"
		if !now.Before(a.backupWebDAVRetry) {
			a.startScheduledWebDAV(state, raw, now)
		} else {
			a.backupCheckAfter = a.backupWebDAVRetry
		}
		return
	}
	dir := a.dir
	var fingerprint string
	var queued queuedWebDAVBackup
	_, err = a.beginArchiveJob("scheduled", now, func(jobErr error) {
		a.backupAutoJob = false
		current, currentRaw, loadErr := a.readBackupSchedule()
		if loadErr != nil || !bytes.Equal(raw, currentRaw) {
			return
		}
		if jobErr == nil {
			current.NextRun = time.Now().UTC().Add(time.Duration(current.IntervalHours) * time.Hour)
			if current.OnChange {
				current.Baseline = fingerprint
			}
			if current.WebDAV {
				if len(current.WebDAVQueue) >= scheduleLimit {
					jobErr = errors.New("WebDAV upload queue is full")
				} else {
					current.WebDAVQueue = append(current.WebDAVQueue, queued)
					current.WebDAVPending = len(current.WebDAVQueue)
				}
			}
			if jobErr == nil {
				jobErr = a.writeBackupState(current, raw)
			}
		}
		if jobErr != nil {
			a.backupRetry = time.Now().Add(autoRetryDelay)
			a.backupCheckAfter = time.Time{}
			a.backupScheduleError = "automatic backup failed; check destination, archive limit and configuration activity"
			if a.model != nil {
				a.model.Notice = "自动备份失败；检查目录、备份数量和配置变动，15 分钟后重试"
			}
		} else {
			a.backupScheduleError = ""
			a.backupChangeDue = time.Time{}
			a.backupInventory = "" // Reconcile edits that occurred after archive capture.
			a.backupCheckAfter = time.Time{}
			if a.model != nil {
				a.model.BackupSchedule = current.BackupSchedule
				a.model.Notice = "自动备份已创建"
			}
		}
	}, func(ctx context.Context) error {
		path, err := scheduledDestination(ctx, s.Directory, now)
		if err != nil {
			return err
		}
		manifest, err := backup.ExportRunning(ctx, dir, path)
		if err != nil {
			return err
		}
		if s.OnChange {
			fingerprint, err = backup.ManifestFingerprint(manifest)
			if err != nil {
				return err
			}
		}
		if s.WebDAV {
			f, err := safepath.OpenRead(filepath.Dir(path), filepath.Base(path))
			if err != nil {
				return err
			}
			info, statErr := f.Stat()
			if statErr != nil {
				f.Close()
				return statErr
			}
			digest, digestErr := archiveDigest(ctx, f, info.Size())
			closeErr := f.Close()
			if digestErr != nil {
				return digestErr
			}
			if closeErr != nil {
				return closeErr
			}
			queued = queuedWebDAVBackup{Name: filepath.Base(path), Digest: hex.EncodeToString(digest[:])}
		}
		return nil
	})
	if err != nil {
		a.backupRetry = now.Add(autoRetryDelay)
		a.backupScheduleError = "automatic backup unavailable; check directory and archive limit"
		if a.model != nil {
			a.model.Notice = "自动备份失败；检查目标目录和备份数量"
		}
	} else {
		a.backupAutoJob = true
	}
}

// A durable queue ensures an upload failure does not silently discard the
// corresponding local snapshot. A crash after server success can duplicate a
// remote object because generic WebDAV has no reliable transactional receipt.
func (a *App) startScheduledWebDAV(state backupScheduleState, raw []byte, now time.Time) {
	binding, err := a.webDAVScheduleBinding()
	if err != nil || binding != state.WebDAVBinding {
		a.backupWebDAVError = "automatic WebDAV upload stopped; saved settings changed or are unavailable"
		a.backupWebDAVRetry = now.Add(autoRetryDelay)
		a.backupCheckAfter = time.Time{}
		if a.model != nil {
			a.model.Notice = "自动上传已暂停；已保存的 WebDAV 设置发生变化或不可用"
		}
		return
	}
	item := state.WebDAVQueue[0]
	decoded, err := hex.DecodeString(item.Digest)
	if err != nil || len(decoded) != sha256.Size {
		a.backupWebDAVError = "invalid queued archive digest"
		a.backupWebDAVRetry = now.Add(autoRetryDelay)
		return
	}
	var expected [32]byte
	copy(expected[:], decoded)
	path := filepath.Join(state.Directory, item.Name)
	_, err = a.beginWebDAVUploadChecked(agent.WebDAVUploadArgs{Archive: path, UseSaved: true}, now, func(_ string, jobErr error) {
		a.backupAutoJob = false
		current, currentRaw, loadErr := a.readBackupSchedule()
		if loadErr != nil || !bytes.Equal(raw, currentRaw) {
			return
		}
		if jobErr == nil {
			current.WebDAVQueue = current.WebDAVQueue[1:]
			current.WebDAVPending = len(current.WebDAVQueue)
			jobErr = a.writeBackupState(current, raw)
		}
		if jobErr != nil {
			a.backupWebDAVError = "automatic WebDAV upload failed; the remote file may be incomplete"
			a.backupWebDAVRetry = time.Now().Add(autoRetryDelay)
			if a.model != nil {
				a.model.Notice = "自动上传失败，15 分钟后重试；远端可能有不完整文件"
			}
		} else {
			a.backupWebDAVError, a.backupWebDAVRetry = "", time.Time{}
			if a.backupScheduleError == "automatic backup waiting; WebDAV upload queue is full" {
				a.backupScheduleError = ""
			}
			if a.model != nil {
				a.model.BackupSchedule = current.BackupSchedule
				a.model.Notice = "自动备份已上传 WebDAV"
			}
		}
		a.backupCheckAfter = time.Time{}
	}, &expected)
	if err != nil {
		a.backupWebDAVError = "automatic WebDAV upload could not start"
		a.backupWebDAVRetry = now.Add(autoRetryDelay)
		a.backupCheckAfter = time.Time{}
	} else {
		a.backupAutoJob = true
	}
}
