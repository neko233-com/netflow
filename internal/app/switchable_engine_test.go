package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/rules"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
)

type switchTestEngine struct {
	coreEngine
	running                                 bool
	tun                                     bool
	onReload                                func()
	selection                               string
	dir, id                                 string
	failStart                               bool
	closed                                  bool
	starts, stops, subscribes, unsubscribes int
	onStart                                 func()
	warning                                 string
	proxyProviders                          []core.ProxyProvider
	ruleProviders                           []rules.Provider
	transform                               func([]byte, string) ([]byte, error)
}

func (e *switchTestEngine) Status() core.Status {
	return core.Status{Running: e.running, TUN: e.tun, ConfigDir: e.dir}
}
func (e *switchTestEngine) EffectiveConfig() ([]byte, error) {
	return os.ReadFile(filepath.Join(e.dir, "config.yaml"))
}
func (e *switchTestEngine) Start(dir string) error {
	e.starts++
	if e.onStart != nil {
		e.onStart()
	}
	if e.failStart {
		return errors.New("start denied")
	}
	e.running = true
	e.dir = dir
	return nil
}
func (e *switchTestEngine) Group(name string) (core.ProxyGroup, error) {
	return core.ProxyGroup{Name: name, Type: "Selector", Now: e.selection, Nodes: []core.ProxyNode{{Name: "DIRECT"}, {Name: "REJECT"}}}, nil
}
func (e *switchTestEngine) Select(_, name string) error          { e.selection = name; return nil }
func (e *switchTestEngine) Selected(string) (string, error)      { return e.selection, nil }
func (e *switchTestEngine) ProxyProviders() []core.ProxyProvider { return e.proxyProviders }
func (e *switchTestEngine) RuleProviders() []rules.Provider      { return e.ruleProviders }
func (e *switchTestEngine) Rules() []rules.Item                  { return nil }
func (e *switchTestEngine) Reload() error {
	if e.onReload != nil {
		e.onReload()
	}
	return nil
}
func (e *switchTestEngine) Stop() error                                            { e.stops++; e.running = false; return nil }
func (e *switchTestEngine) SetTransformer(fn func([]byte, string) ([]byte, error)) { e.transform = fn }
func (e *switchTestEngine) SetProfileID(id string)                                 { e.id = id }
func (e *switchTestEngine) ProfileID() string                                      { return e.id }
func (e *switchTestEngine) SubscribeLogs(func(string, string)) func() {
	e.subscribes++
	return func() { e.unsubscribes++ }
}
func (e *switchTestEngine) Close() error         { e.closed = true; return nil }
func (e *switchTestEngine) CacheWarning() string { return e.warning }

type blockedDelayEngine struct {
	*switchTestEngine
	started chan struct{}
	release chan struct{}
}

func (e *blockedDelayEngine) TestDelay(_, _, _ string, _ time.Duration) (int, error) {
	close(e.started)
	<-e.release
	return 42, nil
}

func TestHandoffDoesNotWaitForDelayAndRejectsOldResult(t *testing.T) {
	old := &blockedDelayEngine{switchTestEngine: &switchTestEngine{running: true, dir: "config"}, started: make(chan struct{}), release: make(chan struct{})}
	next := &switchTestEngine{}
	s := newSwitchableEngine(old)
	result := make(chan error, 1)
	go func() { _, err := s.TestDelay("", "DIRECT", "https://example.test", time.Minute); result <- err }()
	<-old.started
	handoff := make(chan error, 1)
	go func() { handoff <- s.replace(next, nil, nil, nil) }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(old.release)
		t.Fatal("kernel handoff waited for network probe")
	}
	close(old.release)
	if err := <-result; err == nil {
		t.Fatal("result from replaced kernel was accepted")
	}
	if !next.running || !old.closed {
		t.Fatal("handoff did not complete")
	}
}

type blockedProviderEngine struct {
	*switchTestEngine
	started chan struct{}
	release chan struct{}
}

type stoppedBeforeFinalizeEngine struct{ *switchTestEngine }

func (e *stoppedBeforeFinalizeEngine) Stop() error {
	e.running = false
	return coreipc.ErrKernelStoppedBeforeFinalization
}

func TestHandoffRestartsOldKernelAfterInterruptedStopFinalizationFails(t *testing.T) {
	old := &stoppedBeforeFinalizeEngine{&switchTestEngine{running: true, dir: "config", id: "profile"}}
	next := &switchTestEngine{}
	s := newSwitchableEngine(old)
	err := s.replace(next, nil, nil, nil)
	if !errors.Is(err, coreipc.ErrKernelStoppedBeforeFinalization) || !old.running || old.starts != 1 || !next.closed {
		t.Fatalf("old kernel was not restarted after stop finalization failed: %v", err)
	}
}

func (e *blockedProviderEngine) UpdateProxyProvider(string) error {
	close(e.started)
	<-e.release
	return nil
}

func TestBusyProviderRejectsHandoffWithoutWaiting(t *testing.T) {
	old := &blockedProviderEngine{switchTestEngine: &switchTestEngine{running: true, dir: "config"}, started: make(chan struct{}), release: make(chan struct{})}
	s := newSwitchableEngine(old)
	finished := make(chan error, 1)
	go func() { finished <- s.UpdateProxyProvider("provider") }()
	<-old.started
	next := &switchTestEngine{}
	handoff := make(chan error, 1)
	go func() { handoff <- s.replace(next, nil, nil, nil) }()
	select {
	case err := <-handoff:
		if err == nil || !next.closed || !old.running {
			t.Fatal("busy handoff did not preserve old kernel and close the unused one")
		}
	case <-time.After(2 * time.Second):
		close(old.release)
		t.Fatal("handoff waited for provider update")
	}
	close(old.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := s.replace(&switchTestEngine{}, nil, nil, nil); err != nil {
		t.Fatalf("handoff after update: %v", err)
	}
}

func TestHandoffPreservesProviderCacheWarning(t *testing.T) {
	old := &switchTestEngine{running: true, dir: t.TempDir(), warning: "cache conflict"}
	next := &switchTestEngine{}
	s := newSwitchableEngine(old)
	if err := s.replace(next, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := s.CacheWarning(); got != "cache conflict" {
		t.Fatalf("cache warning lost: %q", got)
	}
}

func TestSwitchEngineTransfersStateAndLogs(t *testing.T) {
	old := &switchTestEngine{running: true, dir: "config", id: "profile"}
	next := &switchTestEngine{}
	s := newSwitchableEngine(old)
	s.SetTransformer(func(b []byte, id string) ([]byte, error) { return b, nil })
	stop := s.SubscribeLogs(func(string, string) {})
	if err := s.replace(next, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if old.running || !old.closed || !next.running || next.dir != "config" || next.id != "profile" || next.transform == nil {
		t.Fatal("kernel state was not handed over")
	}
	if old.unsubscribes != 1 || next.subscribes != 1 {
		t.Fatal("logs were not transferred")
	}
	stop()
	if next.unsubscribes != 1 {
		t.Fatal("replacement log subscription was not stopped")
	}
}

func TestSwitchEngineRollsBackStagedState(t *testing.T) {
	staged := false
	old := &switchTestEngine{running: true, dir: "config", id: "profile", onStart: func() {
		if staged {
			t.Error("settings not rolled back before restart")
		}
	}}
	next := &switchTestEngine{failStart: true}
	s := newSwitchableEngine(old)
	stop := s.SubscribeLogs(func(string, string) {})
	defer stop()
	err := s.replace(next, func() error { staged = true; return nil }, nil, func() error { staged = false; return nil })
	if err == nil || staged || !old.running || !next.closed || old.starts != 1 || next.stops != 1 {
		t.Fatalf("rollback failed: %v, old=%+v, next=%+v", err, old, next)
	}
	if old.subscribes != 2 || old.unsubscribes != 1 {
		t.Fatal("original log subscription was not restored")
	}
}

func TestWorkerTUNCommitAndRollback(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	for _, fail := range []bool{false, true} {
		store := appconfig.NewMemory(t.TempDir())
		old := &switchTestEngine{running: true, dir: "config", id: "profile"}
		next := &switchTestEngine{failStart: fail}
		a := &App{store: store, tun: tun.NewMemory(), core: newSwitchableEngine(old)}
		a.localCoreFactory = func() coreEngine { return old }
		next.onReload = func() { next.tun = a.settings.TUN }
		err := a.enableWorkerTUN(next)
		if (err != nil) != fail {
			t.Fatalf("fail=%v: %v", fail, err)
		}
		saved, loadErr := store.Load()
		if loadErr != nil || saved.TUN == fail || a.privilegedTUN == fail {
			t.Fatalf("fail=%v saved=%+v privileged=%v", fail, saved, a.privilegedTUN)
		}
		if fail && (!old.running || !next.closed) {
			t.Fatal("failed worker left the old kernel stopped")
		}
	}
}

func TestWorkerTUNPersistenceFailureRestoresKernel(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	store := appconfig.NewMemory(t.TempDir())
	store.FailSave(errors.New("disk unavailable"))
	old := &switchTestEngine{running: true, dir: "config"}
	next := &switchTestEngine{}
	a := &App{store: store, tun: tun.NewMemory(), core: newSwitchableEngine(old)}
	a.localCoreFactory = func() coreEngine { return old }
	next.onReload = func() { next.tun = a.settings.TUN }
	if err := a.enableWorkerTUN(next); err == nil {
		t.Fatal("failed save accepted")
	}
	if !old.running || !next.closed || a.settings.TUN || a.privilegedTUN {
		t.Fatal("save failure was not rolled back")
	}
}

func TestTUNOffStaysOffWhenPersistenceFails(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	store.FailSave(errors.New("disk unavailable"))
	engine := &switchTestEngine{running: true, tun: true}
	a := &App{store: store, core: engine, settings: appconfig.Settings{TUN: true}}
	engine.onReload = func() { engine.tun = a.settings.TUN }
	err := a.setDirectTUN(false)
	if err == nil || a.settings.TUN || engine.tun {
		t.Fatalf("TUN did not stay off after save failure: %v settings=%v actual=%v", err, a.settings.TUN, engine.tun)
	}
}

type busyTUNEngine struct {
	*switchTestEngine
	busy                  bool
	tryCalls, reloadCalls int
}

func (e *busyTUNEngine) TryReload() error {
	e.tryCalls++
	if e.busy {
		return coreipc.ErrKernelBusy
	}
	return e.switchTestEngine.Reload()
}
func (e *busyTUNEngine) Reload() error { e.reloadCalls++; return e.switchTestEngine.Reload() }

func TestTUNBusyReloadRestoresSettingsWithoutRetryingReload(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	settings := appconfig.Settings{TUN: true}
	if err := store.Save(settings); err != nil {
		t.Fatal(err)
	}
	controller := tun.NewMemory()
	if err := controller.Set(true); err != nil {
		t.Fatal(err)
	}
	engine := &busyTUNEngine{switchTestEngine: &switchTestEngine{running: true, tun: true}, busy: true}
	a := &App{store: store, tun: controller, core: newSwitchableEngine(engine), settings: settings}
	engine.onReload = func() { engine.tun = a.settings.TUN }
	err := a.setDirectTUN(false)
	if !errors.Is(err, coreipc.ErrKernelBusy) || !a.settings.TUN || !engine.tun || engine.tryCalls != 1 || engine.reloadCalls != 0 {
		t.Fatalf("busy TUN request changed state or retried reload: %v settings=%+v", err, a.settings)
	}
	saved, err := store.Load()
	if err != nil || !saved.TUN {
		t.Fatalf("busy request changed persisted settings: %+v %v", saved, err)
	}
	engine.busy = false
	if err := a.setDirectTUN(false); err != nil || a.settings.TUN || engine.tun {
		t.Fatalf("retry did not stop TUN: %v", err)
	}
}

type blockedBusyWorker struct {
	*busyTUNEngine
	started, release chan struct{}
	stopError        error
}

func (e *blockedBusyWorker) Stop() error {
	close(e.started)
	<-e.release
	if e.stopError != nil {
		if errors.Is(e.stopError, coreipc.ErrKernelStoppedBeforeFinalization) {
			e.running, e.tun = false, false
		}
		return e.stopError
	}
	e.running, e.tun = false, false
	return nil
}

func TestBusyWorkerTUNOffStopsAsynchronouslyAndRecovers(t *testing.T) {
	for _, tc := range []struct {
		name                                        string
		failStart, failSave, failStop, failFinalize bool
	}{
		{name: "success"}, {name: "local start failure", failStart: true}, {name: "settings failure", failSave: true}, {name: "stop failure", failStop: true},
		{name: "stop finalization failure", failFinalize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := appconfig.NewMemory(t.TempDir())
			settings := appconfig.Settings{TUN: true}
			if err := store.Save(settings); err != nil {
				t.Fatal(err)
			}
			if tc.failSave {
				store.FailSave(errors.New("synthetic settings failure"))
			}
			old := &blockedBusyWorker{busyTUNEngine: &busyTUNEngine{switchTestEngine: &switchTestEngine{running: true, tun: true, dir: "config", id: "profile"}, busy: true}, started: make(chan struct{}), release: make(chan struct{})}
			if tc.failStop {
				old.stopError = errors.New("synthetic stop failure")
			}
			if tc.failFinalize {
				old.stopError = coreipc.ErrKernelStoppedBeforeFinalization
			}
			next := &switchTestEngine{failStart: tc.failStart}
			dispatch := newSerialDispatcher()
			defer dispatch.close()
			a := &App{store: store, core: newSwitchableEngine(old), settings: settings, privilegedTUN: true, dispatch: dispatch.call, localCoreFactory: func() coreEngine { return next }}
			old.onStart = func() { old.tun = a.settings.TUN }
			result := make(chan error, 1)
			dispatch.call(func() { a.requestTUN(false, func(err error) { result <- err }) })
			select {
			case <-old.started:
			case <-time.After(5 * time.Second):
				t.Fatal("worker stop did not start")
			}
			var pending bool
			var updateErr error
			var mutationErrors []error
			dispatch.call(func() {
				pending = a.tunBusy
				a.updateProxyProviderAsync("x", func(err error) { updateErr = err })
				mutationErrors = []error{a.UseProfile("x"), a.SelectProxy("g", "n"), a.SetMode("rule"), a.DeleteProfile("x"), a.ImportLocal("missing"), a.setProfileDNS("x", false, ""), a.restartCore()}
			})
			if !pending || updateErr == nil {
				close(old.release)
				t.Fatal("transition did not block new provider updates")
			}
			for _, mutationErr := range mutationErrors {
				if mutationErr == nil || !strings.Contains(mutationErr.Error(), "虚拟网卡正在切换") {
					close(old.release)
					t.Fatalf("mutation not blocked during transition: %v", mutationErr)
				}
			}
			select {
			case <-result:
				close(old.release)
				t.Fatal("request completed before worker stopped")
			default:
			}
			close(old.release)
			var err error
			select {
			case err = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("TUN off did not finish")
			}
			var current appconfig.Settings
			var privileged, busy bool
			dispatch.call(func() { current = a.settings; privileged = a.privilegedTUN; busy = a.tunBusy })
			if busy {
				t.Fatal("transition remained busy")
			}
			if tc.failStop {
				if err == nil || !current.TUN || !old.running || !old.tun {
					t.Fatalf("failed stop changed state: %v %+v", err, current)
				}
				return
			}
			if current.TUN {
				t.Fatal("TUN setting remained on")
			}
			if tc.failStart {
				if err == nil || !privileged || !old.running || old.tun {
					t.Fatalf("old worker was not restored with TUN off: %v", err)
				}
			} else if !next.running || privileged || ((tc.failSave || tc.failFinalize) && err == nil) || (!tc.failSave && !tc.failFinalize && err != nil) {
				t.Fatalf("unexpected handoff state: err=%v privileged=%v", err, privileged)
			}
			if !tc.failSave {
				saved, e := store.Load()
				if e != nil || saved.TUN {
					t.Fatalf("TUN off was not saved: %+v %v", saved, e)
				}
			}
		})
	}
}

func TestAgentTUNOffReportsPendingWithoutWaitingForBusyWorker(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	settings := appconfig.Settings{TUN: true}
	if err := store.Save(settings); err != nil {
		t.Fatal(err)
	}
	old := &blockedBusyWorker{busyTUNEngine: &busyTUNEngine{switchTestEngine: &switchTestEngine{running: true, tun: true, dir: "config", id: "profile"}, busy: true}, started: make(chan struct{}), release: make(chan struct{})}
	next := &switchTestEngine{}
	dispatch := newSerialDispatcher()
	defer dispatch.close()
	a := &App{store: store, core: newSwitchableEngine(old), settings: settings, privilegedTUN: true, dispatch: dispatch.call, localCoreFactory: func() coreEngine { return next }}
	var value any
	var err error
	dispatch.call(func() { value, err = a.agentCommand("tun", json.RawMessage(`{"enabled":false}`)) })
	result, ok := value.(agent.TunResult)
	if err != nil || !ok || !result.Accepted || !result.Pending || !result.TUN {
		close(old.release)
		t.Fatalf("unexpected pending result: %+v %v", value, err)
	}
	select {
	case <-old.started:
	case <-time.After(5 * time.Second):
		close(old.release)
		t.Fatal("worker stop did not start")
	}
	close(old.release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var pending bool
		dispatch.call(func() { pending = a.tunBusy })
		if !pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("TUN transition remained pending")
}

func TestBusyWorkerHandoffRetriesWhileReaderFinishes(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	settings := appconfig.Settings{TUN: true}
	if err := store.Save(settings); err != nil {
		t.Fatal(err)
	}
	old := &blockedBusyWorker{busyTUNEngine: &busyTUNEngine{switchTestEngine: &switchTestEngine{running: true, tun: true, dir: "config"}, busy: true}, started: make(chan struct{}), release: make(chan struct{})}
	sw := newSwitchableEngine(old)
	dispatch := newSerialDispatcher()
	defer dispatch.close()
	created := make(chan struct{}, 10)
	a := &App{store: store, core: sw, settings: settings, privilegedTUN: true, dispatch: dispatch.call, localCoreFactory: func() coreEngine { created <- struct{}{}; return &switchTestEngine{} }}
	result := make(chan error, 1)
	dispatch.call(func() { a.requestTUN(false, func(err error) { result <- err }) })
	<-old.started
	sw.mu.RLock()
	close(old.release)
	select {
	case <-created:
	case <-time.After(5 * time.Second):
		sw.mu.RUnlock()
		t.Fatal("handoff did not attempt while reader held lock")
	}
	sw.mu.RUnlock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handoff did not retry")
	}
}

func TestTUNEnableRejectsKnownSettingsConflictBeforeReload(t *testing.T) {
	dir := t.TempDir()
	store := appconfig.NewFileStore(dir)
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	engine := &switchTestEngine{running: true}
	reloaded := false
	engine.onReload = func() { reloaded = true }
	a := &App{store: store, core: engine}
	var result error
	a.requestTUN(true, func(err error) { result = err })
	if result == nil || reloaded || a.tunBusy || a.settings.TUN {
		t.Fatalf("known conflict was not rejected: %v reload=%v busy=%v tun=%v", result, reloaded, a.tunBusy, a.settings.TUN)
	}
}

func TestTUNOffRetriesWorkerRelease(t *testing.T) {
	worker := &switchTestEngine{running: true, dir: "config"}
	local := &switchTestEngine{failStart: true}
	a := &App{store: appconfig.NewMemory(t.TempDir()), core: newSwitchableEngine(worker), privilegedTUN: true}
	a.localCoreFactory = func() coreEngine { return local }
	if err := a.setDirectTUN(false); err == nil || !a.privilegedTUN {
		t.Fatalf("expected a failed release: %v", err)
	}
	local.failStart = false
	if err := a.setDirectTUN(false); err != nil || a.privilegedTUN {
		t.Fatalf("retry failed: %v privileged=%v", err, a.privilegedTUN)
	}
}

func TestAgentTUNCommandIsExplicit(t *testing.T) {
	old := &switchTestEngine{running: true, dir: "config"}
	a := &App{store: appconfig.NewMemory(t.TempDir()), tun: tun.NewMemory(), core: newSwitchableEngine(old)}
	if _, err := a.agentCommand("tun", json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing enabled accepted")
	}
	value, err := a.agentCommand("tun", json.RawMessage(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	out, ok := value.(agent.TunResult)
	if !ok || !out.Accepted || out.Pending || out.TUN {
		t.Fatalf("unexpected result %+v", value)
	}
}

func TestWorkerRestoresSelectionBeforeTUNReload(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	dir := t.TempDir()
	config := []byte("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT, REJECT]\nrules: ['MATCH,PROXY']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	old := &switchTestEngine{running: true, dir: dir, id: "profile", selection: "REJECT"}
	next := &switchTestEngine{selection: "DIRECT"}
	model := ui.NewModel(ui.HomeState{})
	model.CurrentProfile = "profile"
	model.Profiles = []ui.ProfileItem{{UID: "profile", Selected: []ui.ProfileSelected{{Name: "PROXY", Now: "REJECT"}}}}
	a := &App{dir: dir, model: model, store: appconfig.NewMemory(dir), tun: tun.NewMemory(), core: newSwitchableEngine(old)}
	a.localCoreFactory = func() coreEngine { return old }
	next.onReload = func() {
		if next.selection != "REJECT" {
			t.Error("TUN enabled before selected node was restored")
		}
		next.tun = a.settings.TUN
	}
	if err := a.enableWorkerTUN(next); err != nil {
		t.Fatal(err)
	}
	if !next.tun || next.selection != "REJECT" || model.Home.RunMode != ui.RunAdmin {
		t.Fatal("worker did not activate with the saved node and privileged status")
	}
	if err := a.SetTUN(false); err != nil {
		t.Fatal(err)
	}
	if a.privilegedTUN || model.Home.TUN || model.Home.RunMode != ui.RunSidecar {
		t.Fatal("disabling TUN did not restore the normal kernel status")
	}
}
