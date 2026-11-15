package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type agentRollbackGateEngine struct {
	coreEngine
	calls, cancels             atomic.Int32
	entered, release, canceled chan struct{}
	once                       sync.Once
}

type delayedDirectCancelEngine struct {
	coreEngine
	entered, release chan struct{}
}

func (e *delayedDirectCancelEngine) CancelActiveApply(ctx context.Context) (bool, error) {
	close(e.entered)
	select {
	case <-e.release:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func TestDirectAgentCancelCannotReachNewTransaction(t *testing.T) {
	d := newSerialDispatcher()
	defer d.close()
	engine := &delayedDirectCancelEngine{entered: make(chan struct{}), release: make(chan struct{})}
	a := &App{core: engine, dispatch: d.call}
	finished := make(chan error, 1)
	go func() {
		_, err := a.dispatchAgent(context.Background(), "cancel-apply", json.RawMessage(`{}`))
		finished <- err
	}()
	select {
	case <-engine.entered:
	case <-time.After(time.Second):
		t.Fatal("direct cancellation did not start")
	}
	startResult := make(chan error, 1)
	d.call(func() {
		a.startGUIConfigOperation("test", func() (*guiConfigTransaction, error) {
			t.Error("transaction began while direct cancellation was active")
			return nil, nil
		}, func(err error) { startResult <- err })
	})
	if err := <-startResult; err == nil || a.guiBarrier.Load() != nil {
		t.Fatal("new transaction was not rejected during direct cancellation")
	}
	close(engine.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct cancellation did not finish")
	}
	completed := make(chan error, 1)
	d.call(func() {
		a.startGUIConfigOperation("test", func() (*guiConfigTransaction, error) {
			return &guiConfigTransaction{commit: func() error { return nil }}, nil
		}, func(err error) { completed <- err })
	})
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new transaction did not resume after cancellation")
	}
}

func TestTimedOutDirectCancelKeepsNewTransactionsOutUntilDeadline(t *testing.T) {
	d := newSerialDispatcher()
	defer d.close()
	engine := &delayedDirectCancelEngine{entered: make(chan struct{}), release: make(chan struct{})}
	a := &App{core: engine, dispatch: d.call}
	deadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := a.dispatchAgent(ctx, "cancel-apply", json.RawMessage(`{}`)); finished <- err }()
	select {
	case <-engine.entered:
	case <-time.After(time.Second):
		t.Fatal("direct cancellation did not start")
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("direct cancellation result: %v", err)
	}
	tryStart := func() <-chan error {
		done := make(chan error, 1)
		d.call(func() {
			a.startGUIConfigOperation("test", func() (*guiConfigTransaction, error) {
				return &guiConfigTransaction{commit: func() error { return nil }}, nil
			}, func(err error) { done <- err })
		})
		return done
	}
	if err := <-tryStart(); err == nil {
		t.Fatal("new transaction started before the remote cancellation deadline")
	}
	if remaining := time.Until(deadline); remaining > 0 {
		<-time.After(remaining + 50*time.Millisecond)
	}
	select {
	case err := <-tryStart():
		if err != nil {
			t.Fatalf("new transaction stayed blocked after the deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new transaction did not finish")
	}
}

func (e *agentRollbackGateEngine) Reload() error {
	if e.calls.Add(1) == 1 {
		return errors.New("injected application failure")
	}
	close(e.entered)
	select {
	case <-e.release:
		return e.coreEngine.Reload()
	case <-e.canceled:
		return context.Canceled
	}
}

func (e *agentRollbackGateEngine) CancelActiveApply(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	e.cancels.Add(1)
	e.once.Do(func() { close(e.canceled) })
	return true, nil
}

func TestAgentCancelDoesNotInterruptRollback(t *testing.T) {
	for _, headless := range []bool{false, true} {
		t.Run(map[bool]string{false: "gui", true: "headless"}[headless], func(t *testing.T) {
			t.Setenv("CI", "1")
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			underlying := a.core
			defer underlying.Stop()
			engine := &agentRollbackGateEngine{coreEngine: underlying, entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
			a.core = engine
			a.headless = headless
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			go func() {
				_, err := a.dispatchAgent(context.Background(), "mode", json.RawMessage(`{"mode":"direct"}`))
				result <- err
			}()
			select {
			case <-engine.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("rollback reload did not start")
			}
			value, err := a.dispatchAgent(context.Background(), "cancel-apply", json.RawMessage(`{}`))
			if err != nil || value.(agent.CancelApplyResult).Accepted || engine.cancels.Load() != 0 {
				t.Errorf("Agent interrupted rollback: %+v %v", value, err)
			}
			close(engine.release)
			select {
			case err := <-result:
				if err == nil {
					t.Error("failed application reported success")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("rollback did not finish")
			}
			if engine.cancels.Load() != 0 || a.kernelOptions.Snapshot().Mode != nil {
				t.Error("rollback was interrupted or did not restore options")
			}
		})
	}
}
