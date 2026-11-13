package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/core"
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
	transform                               func([]byte, string) ([]byte, error)
}

func (e *switchTestEngine) Status() core.Status {
	return core.Status{Running: e.running, TUN: e.tun, ConfigDir: e.dir}
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
func (e *switchTestEngine) ProxyProviders() []core.ProxyProvider { return nil }
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
func (e *switchTestEngine) Close() error { e.closed = true; return nil }

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
