package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/webdav"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func archiveDigest(ctx context.Context, f *os.File, size int64) ([32]byte, error) {
	var result [32]byte
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx: ctx, reader: io.LimitReader(f, size+1)})
	if err != nil {
		return result, err
	}
	if n != size {
		return result, errors.New("archive size changed")
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}

func (a *App) beginWebDAVUpload(args agent.WebDAVUploadArgs, now time.Time, done func(string, error)) (agent.BackupJob, error) {
	if !validArchivePath(args.Archive) {
		return agent.BackupJob{}, errors.New("backup archive must be an absolute path")
	}
	creds := webdav.Credentials{URL: args.URL, User: args.User, Password: args.Password}
	if args.UseSaved {
		if args.URL != "" || args.User != "" || args.Password != "" {
			return agent.BackupJob{}, errors.New("cannot combine saved and supplied WebDAV credentials")
		}
		saved, err := a.savedWebDAV()
		if err != nil {
			return agent.BackupJob{}, errors.New("saved WebDAV credentials are unavailable")
		}
		creds = webdav.Credentials{URL: saved.URL, User: saved.User, Password: saved.Password}
	}
	if err := webdav.Validate(creds); err != nil {
		return agent.BackupJob{}, err
	}
	archive := args.Archive
	client := webdav.Client{}
	if a.webDAVClient != nil {
		client = *a.webDAVClient
	}
	var job agent.BackupJob
	var remoteName string
	assigned := make(chan struct{})
	job, err := a.beginArchiveJob("webdav-upload", now, func(err error) {
		<-assigned
		if record, ok := a.backupJobs[job.JobID]; ok {
			record.job.RemoteName = remoteName
			a.backupJobs[job.JobID] = record
		}
		if done != nil {
			done(remoteName, err)
		}
	}, func(ctx context.Context) error {
		f, err := safepath.OpenRead(filepath.Dir(archive), filepath.Base(archive))
		if err != nil {
			return errors.New("backup archive could not be opened")
		}
		defer f.Close()
		before, err := f.Stat()
		if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > webdav.MaxArchiveBytes {
			return errors.New("invalid backup archive size")
		}
		first, err := archiveDigest(ctx, f, before.Size())
		if err != nil {
			return errors.New("backup archive could not be read")
		}
		if _, err := backup.InspectFile(ctx, f); err != nil {
			return errors.New("backup archive is invalid")
		}
		validated, err := archiveDigest(ctx, f, before.Size())
		if err != nil || validated != first {
			return errors.New("backup archive changed during validation")
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return errors.New("backup archive could not be read")
		}
		remoteName, err = client.Upload(ctx, creds, f, before.Size())
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return errors.New("backup archive changed; remote file may be incomplete")
		}
		second, err := archiveDigest(ctx, f, before.Size())
		if err != nil || first != second {
			return errors.New("backup archive changed; remote file may be incomplete")
		}
		return nil
	})
	close(assigned)
	return job, err
}
