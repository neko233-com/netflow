package app

import (
	"errors"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/ui"
)

type fakeShortcuts struct {
	registered map[string]func()
	fail       string
}

func (f *fakeShortcuts) Register(key string, fn func()) error {
	if key == f.fail {
		return errors.New("occupied")
	}
	f.registered[key] = fn
	return nil
}
func (f *fakeShortcuts) Unregister(key string) { delete(f.registered, key) }

func TestHotkeysRollbackOnConflictAndPersistenceFailure(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	shortcuts := &fakeShortcuts{registered: map[string]func(){}}
	a := New(Options{Store: store})
	a.model = ui.NewModel(ui.HomeState{})
	a.shortcuts = shortcuts
	initial := a.model.Prefs
	initial.HotkeyDash = "Ctrl+Shift+A"
	if err := a.applyHotkeys(initial); err != nil {
		t.Fatal(err)
	}
	next := initial
	next.HotkeyProxy = "Ctrl+Shift+B"
	next.HotkeyRule = "Ctrl+Shift+C"
	shortcuts.fail = "Ctrl+Shift+C"
	if err := a.applyHotkeys(next); err == nil {
		t.Fatal("conflicting key accepted")
	}
	if len(shortcuts.registered) != 1 || shortcuts.registered["Ctrl+Shift+A"] == nil {
		t.Fatalf("old shortcut lost: %+v", shortcuts.registered)
	}
	shortcuts.fail = ""
	store.FailSave(errors.New("disk"))
	if err := a.applyHotkeys(next); err == nil {
		t.Fatal("failed persistence accepted")
	}
	if len(shortcuts.registered) != 1 || a.model.Prefs.HotkeyProxy != "" {
		t.Fatal("failed save changed shortcuts or preferences")
	}
	store.FailSave(nil)
	if err := a.applyHotkeys(next); err != nil {
		t.Fatal(err)
	}
	if len(shortcuts.registered) != 3 || a.model.Prefs.HotkeyProxy != "Ctrl+Shift+B" {
		t.Fatal("shortcuts not committed")
	}
	a.releaseHotkeys()
	if len(shortcuts.registered) != 0 {
		t.Fatal("shortcuts not released")
	}
}
