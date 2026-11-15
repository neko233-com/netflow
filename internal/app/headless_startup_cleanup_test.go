package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type startupFailureStore struct {
	*appconfig.Memory
	loadErr error
	cancel  context.CancelFunc
}

func (s *startupFailureStore) Load() (appconfig.Settings, error) {
	if s.cancel != nil {
		s.cancel()
	}
	return appconfig.Settings{}, s.loadErr
}

type startupStopFailureEngine struct {
	coreEngine
	startErr error
	stopErr  error
}

func (e *startupStopFailureEngine) StartContext(context.Context, string) error { return e.startErr }
func (e *startupStopFailureEngine) Stop() error                                { return e.stopErr }

func TestHeadlessStartupRetainsCleanupFailures(t *testing.T) {
	startupErr := errors.New("synthetic settings error")
	stopErr := errors.New("synthetic stop failure")
	for _, tc := range []struct {
		name, failure string
		cancel        bool
		wantStartup   bool
	}{
		{name: "settings error", wantStartup: true},
		{name: "unrelated error during cancellation", cancel: true, wantStartup: true},
		{name: "canceled settings load", cancel: true, failure: "canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &startupFailureStore{Memory: appconfig.NewMemory(dir), loadErr: startupErr}
			if tc.cancel {
				store.cancel = cancel
			}
			if tc.failure == "canceled" {
				store.loadErr = context.Canceled
			}
			engine := &startupStopFailureEngine{coreEngine: core.New(), stopErr: stopErr}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			a.core = newSwitchableEngine(engine)
			err := a.RunHeadless(ctx, HeadlessOptions{})
			if !errors.Is(err, stopErr) || errors.Is(err, startupErr) != tc.wantStartup {
				t.Fatalf("startup and cleanup errors: %v", err)
			}
			if errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation to be a normal shutdown: %v", err)
			}
		})
	}
}

func TestHeadlessStoppedCoreReportsCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	stopErr := errors.New("synthetic stop failure")
	engine := &startupStopFailureEngine{coreEngine: core.New(), startErr: errors.New("synthetic core startup failure"), stopErr: stopErr}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
	a.core = newSwitchableEngine(engine)
	err := a.RunHeadless(context.Background(), HeadlessOptions{})
	if !errors.Is(err, stopErr) || !strings.Contains(err.Error(), "synthetic core startup failure") {
		t.Fatalf("core startup and cleanup errors: %v", err)
	}
}
