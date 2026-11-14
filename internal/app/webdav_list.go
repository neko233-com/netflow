package app

import (
	"context"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/webdav"
)

func (a *App) beginWebDAVList(args agent.WebDAVListArgs, now time.Time, done func([]string, error)) (agent.BackupJob, error) {
	creds, err := a.webDAVCredentials(args.URL, args.User, args.Password, args.UseSaved)
	if err != nil {
		return agent.BackupJob{}, err
	}
	client := webdav.Client{}
	if a.webDAVClient != nil {
		client = *a.webDAVClient
	}
	var names []string
	var job agent.BackupJob
	assigned := make(chan struct{})
	job, err = a.beginArchiveJob("webdav-list", now, func(err error) {
		<-assigned
		if record, ok := a.backupJobs[job.JobID]; ok && err == nil {
			record.job.RemoteNames = append([]string(nil), names...)
			a.backupJobs[job.JobID] = record
		}
		if done != nil {
			done(append([]string(nil), names...), err)
		}
	}, func(ctx context.Context) error {
		var listErr error
		names, listErr = client.List(ctx, creds)
		return listErr
	})
	close(assigned)
	return job, err
}
