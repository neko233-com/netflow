package app

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
)

func TestSecondLaunchActivatesExistingInstance(t *testing.T) {
	dir := t.TempDir()
	lock, err := appdir.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	var shown atomic.Bool
	bridge, err := agent.Start(dir, func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		if method == "show" {
			shown.Store(true)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	a := New(Options{Dirs: appdir.Fixed(dir)})
	if err = a.Run(); err != nil {
		t.Fatal(err)
	}
	if !shown.Load() {
		t.Fatal("second launch did not activate existing instance")
	}
}
