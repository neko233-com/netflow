package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/safepath"
)

const backupJobRetention = 10 * time.Minute
const maxBackupJobs = 16

type backupJobRecord struct {
	job         agent.BackupJob
	completedAt time.Time
}

func (a *App) browseBackup() (string, error) {
	return mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.win, Title: "保存本地备份", DefaultPath: "NetFlow-backup.zip", Filters: []mygo.FileFilter{{Name: "NetFlow 备份", Extensions: []string{"zip"}}}})
}

func (a *App) browseBackupDirectory() (string, error) {
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择自动备份目录", Directory: true})
	if err != nil || len(paths) == 0 {
		return "", err
	}
	return paths[0], nil
}

func (a *App) browseWebDAVArchive() (string, error) {
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择要上传的备份", Filters: []mygo.FileFilter{{Name: "NetFlow 备份", Extensions: []string{"zip"}}}})
	if err != nil || len(paths) == 0 {
		return "", err
	}
	return paths[0], nil
}

func (a *App) browseRestore() (string, string, error) {
	archives, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择 NetFlow 备份", Filters: []mygo.FileFilter{{Name: "NetFlow 备份", Extensions: []string{"zip"}}}})
	if err != nil || len(archives) == 0 {
		return "", "", err
	}
	destination, err := a.browseRestoreDestination()
	return archives[0], destination, err
}

func (a *App) browseRestoreDestination() (string, error) {
	parents, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择恢复目录的上一级文件夹", Directory: true})
	if err != nil || len(parents) == 0 {
		return "", err
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := "NetFlow-restored-" + time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(nonce[:])
	return filepath.Join(parents[0], name), nil
}

func validArchivePath(path string) bool {
	return filepath.IsAbs(path) && len(path) <= 32767 && !strings.ContainsRune(path, '\x00')
}

func (a *App) pruneBackupJobs(now time.Time) {
	for id, record := range a.backupJobs {
		if !record.completedAt.IsZero() && now.Sub(record.completedAt) >= backupJobRetention {
			delete(a.backupJobs, id)
		}
	}
}

// beginBackupJob runs on the app event loop; file I/O and compression run in a
// worker. A single in-flight snapshot bounds resource use and avoids overlap.
func (a *App) beginBackupJob(path string, now time.Time, done func(error)) (agent.BackupJob, error) {
	if !validArchivePath(path) {
		return agent.BackupJob{}, errors.New("backup destination must be an absolute path")
	}
	dir := a.dir
	return a.beginArchiveJob("create", now, done, func(ctx context.Context) error {
		_, err := backup.ExportRunning(ctx, dir, path)
		return err
	})
}

func (a *App) beginRestoreJob(archive, destination string, now time.Time, done func(error)) (agent.BackupJob, error) {
	if !validArchivePath(archive) || !validArchivePath(destination) {
		return agent.BackupJob{}, errors.New("restore paths must be absolute")
	}
	config, err := safepath.Canonical(a.dir)
	if err != nil {
		return agent.BackupJob{}, errors.New("configuration directory is unavailable")
	}
	parent, err := safepath.Canonical(filepath.Dir(destination))
	if err != nil {
		return agent.BackupJob{}, errors.New("restore parent directory is unavailable")
	}
	rel, err := filepath.Rel(config, parent)
	if err == nil && (rel == "." || (filepath.IsLocal(rel) && rel != "..")) {
		return agent.BackupJob{}, errors.New("restore destination must be outside the running configuration")
	}
	return a.beginArchiveJob("restore", now, done, func(ctx context.Context) error {
		_, err := backup.RestoreOutside(ctx, archive, destination, config)
		return err
	})
}

func (a *App) beginArchiveJob(operation string, now time.Time, done func(error), work func(context.Context) error) (agent.BackupJob, error) {
	if a.dir == "" || a.core == nil || !a.core.Status().Running {
		return agent.BackupJob{}, errors.New("core is not running")
	}
	if a.tunBusy {
		return agent.BackupJob{}, errors.New("TUN transition in progress")
	}
	if a.backupBusy {
		return agent.BackupJob{}, errors.New("backup or restore is already running")
	}
	if a.backupJobs == nil {
		a.backupJobs = make(map[string]backupJobRecord)
	}
	a.pruneBackupJobs(now)
	if len(a.backupJobs) >= maxBackupJobs {
		var oldestID string
		var oldest time.Time
		for id, record := range a.backupJobs {
			if !record.completedAt.IsZero() && (oldestID == "" || record.completedAt.Before(oldest)) {
				oldestID, oldest = id, record.completedAt
			}
		}
		if oldestID == "" {
			return agent.BackupJob{}, errors.New("backup job capacity reached")
		}
		delete(a.backupJobs, oldestID)
	}
	var id string
	for i := 0; i < 4; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return agent.BackupJob{}, err
		}
		candidate := hex.EncodeToString(random[:])
		if _, exists := a.backupJobs[candidate]; !exists {
			id = candidate
			break
		}
	}
	if id == "" {
		return agent.BackupJob{}, errors.New("could not allocate a backup job id")
	}
	job := agent.BackupJob{JobID: id, Operation: operation, State: "pending", CreatedAt: now.UTC()}
	a.backupJobs[id] = backupJobRecord{job: job}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	a.backupBusy, a.backupCancel, a.backupDone = true, cancel, finished
	if a.model != nil {
		a.model.BackupBusy = true
	}
	go func() {
		err := work(ctx)
		cancel()
		close(finished)
		a.runOnMain(func() {
			a.backupBusy, a.backupCancel, a.backupDone = false, nil, nil
			if a.model != nil {
				a.model.BackupBusy = false
			}
			record, ok := a.backupJobs[id]
			if ok && record.job.State == "pending" {
				record.completedAt = time.Now()
				if err == nil {
					record.job.State = "succeeded"
				} else {
					record.job.State = "failed"
					switch {
					case operation == "webdav-list":
						record.job.Error = "WebDAV listing failed"
					case operation == "webdav-upload":
						record.job.Error = "upload failed; the remote file may be incomplete"
					case errors.Is(err, context.Canceled):
						record.job.Error = "operation canceled; a new restore directory may be partial"
					case errors.Is(err, os.ErrExist):
						record.job.Error = "destination already exists"
					default:
						record.job.Error = "operation failed; inspect any new restore directory before retrying"
					}
				}
				a.backupJobs[id] = record
			}
			if done != nil {
				done(err)
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
	return job, nil
}

func (a *App) getBackupJob(id string, now time.Time) (agent.BackupJob, error) {
	a.pruneBackupJobs(now)
	if len(id) != 32 {
		return agent.BackupJob{}, errors.New("invalid backup job id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return agent.BackupJob{}, errors.New("invalid backup job id")
	}
	record, ok := a.backupJobs[id]
	if !ok {
		return agent.BackupJob{}, errors.New("backup job not found or expired")
	}
	return record.job, nil
}

// stopBackup is called before the core and configuration lock are released.
func (a *App) stopBackup() {
	if a.backupScanCancel != nil {
		a.backupScanCancel()
	}
	if a.backupScanDone != nil {
		<-a.backupScanDone
	}
	if a.backupCancel != nil {
		a.backupCancel()
	}
	if a.backupDone != nil {
		<-a.backupDone
	}
}
