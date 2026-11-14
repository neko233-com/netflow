package app

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestTUNAutoStartIsOptInGUIOnlyAndPersistent(t *testing.T) {
	store := appconfig.NewMemory(t.TempDir())
	a := &App{store: store, model: ui.NewModel(ui.HomeState{})}
	requests := 0
	request := func(on bool, done func(error)) {
		if !on {
			t.Error("startup requested TUN off")
		}
		requests++
		done(nil)
	}
	a.requestPreferredTUN(request)
	if requests != 0 {
		t.Fatal("TUN started without opt-in")
	}
	if err := a.setTUNAutoStart(true); err != nil {
		t.Fatal(err)
	}
	settings, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var prefs ui.Prefs
	if json.Unmarshal([]byte(settings.Prefs), &prefs) != nil || !prefs.AutoStartTUN || settings.TUN {
		t.Fatal("preference not saved independently of current TUN")
	}
	a.requestPreferredTUN(request)
	if requests != 1 {
		t.Fatal("GUI did not request TUN")
	}
	a.headless = true
	a.requestPreferredTUN(request)
	a.headless = false
	a.settings.TUN = true
	a.requestPreferredTUN(request)
	if requests != 1 {
		t.Fatal("headless or already enabled TUN requested again")
	}
	a.settings.TUN = false
	a.tunBusy = true
	if err := a.setTUNAutoStart(false); err == nil || !a.model.Prefs.AutoStartTUN {
		t.Fatal("changed startup preference during TUN transition")
	}
	a.tunBusy = false
	store.FailSave(errors.New("synthetic failure"))
	if err := a.setTUNAutoStart(false); err == nil || !a.model.Prefs.AutoStartTUN {
		t.Fatal("failed save changed startup preference")
	}
}
