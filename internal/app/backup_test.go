package app

import (
	"context"
	"testing"
	"time"
)

func TestBackupWorkerCancelsWhenHeadlessDispatcherStops(t *testing.T) {
	dispatcher := newSerialDispatcher()
	a := &App{dir: t.TempDir(), core: diagnosticsTestEngine{}, dispatch: dispatcher.call}
	started := make(chan struct{})
	var startErr error
	a.runOnMain(func() {
		_, startErr = a.beginArchiveJob("create", time.Now(), nil, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
	})
	if startErr != nil {
		t.Fatal(startErr)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("backup worker did not start")
	}
	dispatcher.close()
	stopped := make(chan struct{})
	go func() { a.stopBackup(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("backup worker did not stop after cancellation")
	}
}
