package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIProfileSwitchRemainsResponsiveAndRollsBack(t *testing.T) {
	for _, scenario := range []string{"cancel", "agent-cancel", "success", "source-changed", "cancel-before-start"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enteredOnce, canceledOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
					canceledOnce.Do(func() { close(canceled) })
				case <-release:
					_, _ = io.WriteString(w, "proxies: [{name: fresh, type: direct}]\n")
				}
			}))
			defer provider.Close()
			defer unblock()
			dir := t.TempDir()
			base := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"
			next := base + "proxy-providers:\n  slow: {type: http, url: '" + provider.URL + "', path: providers/slow.yaml, interval: 3600, health-check: {enable: false}}\n"
			store := profile.NewStore(dir)
			first, err := store.ImportLocal("first.yaml", []byte(base))
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.ImportLocal("second.yaml", []byte(next))
			if err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			before, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			client := agent.Client{Dir: dir, Timeout: 10 * time.Second}
			if scenario == "agent-cancel" {
				if err := a.startAgent(); err != nil {
					t.Fatal(err)
				}
				defer a.stopAgent()
				go func() {
					result <- client.Call(context.Background(), "use-profile", agent.ProfileArgs{ProfileID: second.UID}, nil)
				}()
			} else {
				d.call(func() {
					a.useProfileAsync(second.UID, func(err error) { result <- err })
					if scenario == "cancel-before-start" {
						a.cancelGUIConfigOperation(a.guiOperation)
					}
				})
			}
			if scenario != "cancel-before-start" {
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("provider did not begin")
				}
				// An unrelated native event can execute while mutation callbacks
				// are held until the transaction and rollback have completed.
				pulse := make(chan struct{})
				go d.call(func() { close(pulse) })
				select {
				case <-pulse:
				case <-time.After(time.Second):
					t.Fatal("event loop blocked during reload")
				}
				gated := make(chan struct{})
				go a.runOnMain(func() { close(gated) })
				select {
				case <-gated:
					t.Fatal("mutation callback ran during profile transaction")
				case <-time.After(100 * time.Millisecond):
				}
				switch scenario {
				case "cancel":
					d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
					select {
					case <-canceled:
					case <-time.After(5 * time.Second):
						t.Fatal("provider was not canceled")
					}
				case "agent-cancel":
					var canceledApply agent.CancelApplyResult
					if err := client.Call(context.Background(), "cancel-apply", nil, &canceledApply); err != nil || !canceledApply.Accepted {
						t.Fatalf("Agent cancel: %+v %v", canceledApply, err)
					}
					select {
					case <-canceled:
					case <-time.After(5 * time.Second):
						t.Fatal("Agent did not cancel provider")
					}
				case "source-changed":
					changed := []byte("mode: global\nrules: ['MATCH,DIRECT']\n")
					if err := os.WriteFile(filepath.Join(dir, second.File), changed, 0600); err != nil {
						t.Fatal(err)
					}
					unblock()
				default:
					unblock()
				}
				defer func() {
					select {
					case <-gated:
					case <-time.After(5 * time.Second):
						t.Error("deferred callback did not resume")
					}
				}()
			}
			select {
			case err = <-result:
			case <-time.After(15 * time.Second):
				t.Fatal("profile operation did not finish")
			}
			if scenario == "success" && err != nil {
				t.Fatalf("switch failed: %v", err)
			}
			if scenario != "success" && err == nil {
				t.Fatal("failed switch reported success")
			}
			if scenario == "cancel-before-start" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			var current string
			var busy bool
			d.call(func() { current, busy = a.model.CurrentProfile, a.guiOperation != nil || a.guiBarrier.Load() != nil })
			if busy {
				t.Fatal("operation remained busy")
			}
			catalog, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			want := first.UID
			if scenario == "success" {
				want = second.UID
			}
			if current != want || catalog.Current != want || a.core.ProfileID() != want {
				t.Fatalf("profile was not committed or restored: model=%s catalog=%s core=%s", current, catalog.Current, a.core.ProfileID())
			}
			if scenario != "success" {
				after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("config was not restored: %v", err)
				}
			}
		})
	}
}

type delayedCancelSwitchEngine struct {
	*switchTestEngine
	calls                                         atomic.Int32
	reloadStarted, reloadRelease, rollbackStarted chan struct{}
	cancelStarted, cancelRelease                  chan struct{}
}

func (e *delayedCancelSwitchEngine) Reload() error {
	if e.calls.Add(1) == 1 {
		close(e.reloadStarted)
		<-e.reloadRelease
		return nil
	}
	close(e.rollbackStarted)
	return nil
}

func (e *delayedCancelSwitchEngine) CancelActiveApply(context.Context) (bool, error) {
	close(e.cancelStarted)
	<-e.cancelRelease
	return true, nil
}

func TestGUIProfileCancelCompletesBeforeRollbackStarts(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	base := []byte("mode: rule\nrules: ['MATCH,DIRECT']\n")
	first, err := a.profiles.ImportLocal("first.yaml", base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.profiles.ImportLocal("second.yaml", []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"))
	if err != nil {
		t.Fatal(err)
	}
	a.loadProfiles()
	if err := a.installCurrentProfile(); err != nil {
		t.Fatal(err)
	}
	engine := &delayedCancelSwitchEngine{
		switchTestEngine: &switchTestEngine{running: true, dir: dir, id: first.UID},
		reloadStarted:    make(chan struct{}), reloadRelease: make(chan struct{}), rollbackStarted: make(chan struct{}),
		cancelStarted: make(chan struct{}), cancelRelease: make(chan struct{}),
	}
	a.core = engine
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	result := make(chan error, 1)
	d.call(func() { a.useProfileAsync(second.UID, func(err error) { result <- err }) })
	select {
	case <-engine.reloadStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not start")
	}
	d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
	select {
	case <-engine.cancelStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not start")
	}
	close(engine.reloadRelease)
	select {
	case <-engine.rollbackStarted:
		t.Fatal("rollback began before cancellation returned")
	case <-time.After(100 * time.Millisecond):
	}
	close(engine.cancelRelease)
	select {
	case <-engine.rollbackStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("rollback did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled operation result: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled operation did not finish")
	}
	if engine.ProfileID() != first.UID {
		t.Fatal("previous profile id was not restored")
	}
}

type delayedStartSwitchEngine struct {
	*switchTestEngine
	calls                                 atomic.Int32
	active                                atomic.Bool
	polledOnce, canceledOnce              sync.Once
	started, allowApply, polled, canceled chan struct{}
}

func (e *delayedStartSwitchEngine) Reload() error {
	if e.calls.Add(1) != 1 {
		return nil
	}
	close(e.started)
	<-e.allowApply
	e.active.Store(true)
	<-e.canceled
	return context.Canceled
}

func (e *delayedStartSwitchEngine) CancelActiveApply(context.Context) (bool, error) {
	if !e.active.Load() {
		e.polledOnce.Do(func() { close(e.polled) })
		return false, nil
	}
	e.canceledOnce.Do(func() { close(e.canceled) })
	return true, nil
}

func TestGUIProfileCancelRetriesUntilReloadRegisters(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	first, err := a.profiles.ImportLocal("first.yaml", []byte("mode: rule\nrules: ['MATCH,DIRECT']\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.profiles.ImportLocal("second.yaml", []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"))
	if err != nil {
		t.Fatal(err)
	}
	a.loadProfiles()
	if err := a.installCurrentProfile(); err != nil {
		t.Fatal(err)
	}
	engine := &delayedStartSwitchEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir, id: first.UID},
		started: make(chan struct{}), allowApply: make(chan struct{}), polled: make(chan struct{}), canceled: make(chan struct{})}
	a.core = engine
	d := newSerialDispatcher()
	a.dispatch = d.call
	defer d.close()
	result := make(chan error, 1)
	d.call(func() { a.useProfileAsync(second.UID, func(err error) { result <- err }) })
	select {
	case <-engine.started:
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not start")
	}
	d.call(func() { a.cancelGUIConfigOperation(a.guiOperation) })
	select {
	case <-engine.polled:
	case <-time.After(5 * time.Second):
		t.Fatal("initial cancellation did not reach the engine")
	}
	close(engine.allowApply)
	select {
	case <-engine.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation was lost before apply registration")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled operation result: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled operation did not finish")
	}
	if engine.ProfileID() != first.UID {
		t.Fatal("previous profile id was not restored")
	}
}

type quitRollbackSwitchEngine struct {
	*switchTestEngine
	stage                                                          atomic.Int32
	firstOnce, rollbackOnce                                        sync.Once
	firstStarted, rollbackStarted, firstCanceled, rollbackCanceled chan struct{}
}

func (e *quitRollbackSwitchEngine) Reload() error {
	if e.stage.Add(1) == 1 {
		close(e.firstStarted)
		<-e.firstCanceled
		return context.Canceled
	}
	close(e.rollbackStarted)
	<-e.rollbackCanceled
	return context.Canceled
}

func (e *quitRollbackSwitchEngine) CancelActiveApply(context.Context) (bool, error) {
	if e.stage.Load() == 1 {
		e.firstOnce.Do(func() { close(e.firstCanceled) })
	} else {
		e.rollbackOnce.Do(func() { close(e.rollbackCanceled) })
	}
	return true, nil
}

func TestGUIQuitCancelsOrSkipsStalledProfileRollback(t *testing.T) {
	for _, quitDuringRollback := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback-started=%t", quitDuringRollback), func(t *testing.T) {
			dir := t.TempDir()
			a := newProfileHarness(dir)
			first, err := a.profiles.ImportLocal("first.yaml", []byte("mode: rule\nrules: ['MATCH,DIRECT']\n"))
			if err != nil {
				t.Fatal(err)
			}
			second, err := a.profiles.ImportLocal("second.yaml", []byte("mode: direct\nrules: ['MATCH,DIRECT']\n"))
			if err != nil {
				t.Fatal(err)
			}
			a.loadProfiles()
			if err := a.installCurrentProfile(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			engine := &quitRollbackSwitchEngine{switchTestEngine: &switchTestEngine{running: true, dir: dir, id: first.UID},
				firstStarted: make(chan struct{}), rollbackStarted: make(chan struct{}), firstCanceled: make(chan struct{}), rollbackCanceled: make(chan struct{})}
			a.core = engine
			d := newSerialDispatcher()
			a.dispatch = d.call
			defer d.close()
			result := make(chan error, 1)
			quitCalled := make(chan struct{})
			a.guiQuit = func() { close(quitCalled) }
			var operation *guiConfigOperation
			d.call(func() {
				a.useProfileAsync(second.UID, func(err error) { result <- err })
				operation = a.guiOperation
			})
			select {
			case <-engine.firstStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("reload did not start")
			}
			gated := make(chan struct{})
			go a.runOnMain(func() { close(gated) })
			d.call(func() {
				if !quitDuringRollback {
					operation.quit = true
				}
				a.cancelGUIConfigOperation(operation)
			})
			if quitDuringRollback {
				select {
				case <-engine.rollbackStarted:
				case <-time.After(5 * time.Second):
					t.Fatal("rollback did not start")
				}
				d.call(func() { operation.quit = true; a.cancelGUIConfigOperation(operation) })
				select {
				case <-engine.rollbackCanceled:
				case <-time.After(5 * time.Second):
					t.Fatal("quit did not cancel rollback")
				}
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("operation result: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("quit waited for profile operation")
			}
			select {
			case <-quitCalled:
			case <-time.After(5 * time.Second):
				t.Fatal("GUI quit was not requested")
			}
			select {
			case <-gated:
				t.Fatal("queued mutation ran before the GUI event loop exited")
			case <-time.After(100 * time.Millisecond):
			}
			d.call(func() { a.releaseGUIBarrierAfterExit() })
			select {
			case <-gated:
			case <-time.After(5 * time.Second):
				t.Fatal("queued callback did not leave the barrier after exit")
			}
			if !quitDuringRollback && engine.stage.Load() != 1 {
				t.Fatal("quit unnecessarily started a rollback reload")
			}
			if engine.ProfileID() != first.UID {
				t.Fatal("previous profile id was not restored")
			}
			after, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("previous config was not restored: %v", err)
			}
		})
	}
}
