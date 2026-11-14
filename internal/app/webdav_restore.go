package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/webdav"
)

func (a *App) beginWebDAVRestore(args agent.WebDAVRestoreArgs, now time.Time, done func(error)) (agent.BackupJob, error) {
	if !validArchivePath(args.Destination) || !webdav.ValidRemoteName(args.RemoteName) {
		return agent.BackupJob{}, errors.New("invalid backup name or restore destination")
	}
	creds, err := a.webDAVCredentials(args.URL, args.User, args.Password, args.UseSaved)
	if err != nil {
		return agent.BackupJob{}, err
	}
	config, err := safepath.Canonical(a.dir)
	if err != nil {
		return agent.BackupJob{}, errors.New("configuration directory is unavailable")
	}
	parent, err := safepath.Canonical(filepath.Dir(args.Destination))
	if err != nil {
		return agent.BackupJob{}, errors.New("restore parent directory is unavailable")
	}
	rel, err := filepath.Rel(config, parent)
	if err == nil && (rel == "." || (filepath.IsLocal(rel) && rel != "..")) {
		return agent.BackupJob{}, errors.New("restore destination must be outside the running configuration")
	}
	name := filepath.Base(args.Destination)
	if !filepath.IsLocal(name) || name == "." {
		return agent.BackupJob{}, errors.New("invalid restore destination")
	}
	client := webdav.Client{}
	if a.webDAVClient != nil {
		client = *a.webDAVClient
	}
	return a.beginArchiveJob("webdav-restore", now, done, func(ctx context.Context) error {
		root, err := os.OpenRoot(parent)
		if err != nil {
			return errors.New("restore parent directory is unavailable")
		}
		defer root.Close()
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return os.ErrExist
			}
			return errors.New("restore destination cannot be inspected")
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errors.New("could not allocate temporary download")
		}
		temporary := ".netflow-download-" + hex.EncodeToString(random[:]) + ".zip"
		f, err := root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("could not create temporary download")
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return errors.New("could not inspect temporary download")
		}
		defer func() {
			_ = f.Close()
			if current, err := root.Lstat(temporary); err == nil && current.Mode().IsRegular() && os.SameFile(info, current) {
				_ = root.Remove(temporary)
			}
		}()
		if err := client.Download(ctx, creds, args.RemoteName, f); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return errors.New("could not save temporary download")
		}
		_, err = backup.RestoreOutsideFile(ctx, f, args.Destination, config)
		return err
	})
}
