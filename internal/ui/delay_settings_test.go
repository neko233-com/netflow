package ui

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

func TestDelaySettingsSaveValidationAndOldPreferences(t *testing.T) {
	p := DefaultPrefs()
	if err := json.Unmarshal([]byte(`{"Language":"zh","ProxyColumns":2}`), &p); err != nil {
		t.Fatal(err)
	}
	m := NewModel(HomeState{})
	m.Prefs = p
	if m.delayURL() != defaultDelayURL || m.delayTimeoutMS() != 10000 {
		t.Fatal("old preferences did not retain defaults")
	}
	m.Dialogs.Misc = true
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	var saved Prefs
	m.Hooks.SavePrefs = func(p Prefs) error { saved = p; return nil }
	if err := tt.Click("delay-url"); err != nil {
		t.Fatal(err)
	}
	tt.Key(mygoui.Cmd, mygoui.KeyA)
	tt.Type("https://example.test/check")
	if err := tt.Click("delay-timeout"); err != nil {
		t.Fatal(err)
	}
	tt.Key(mygoui.Cmd, mygoui.KeyA)
	tt.Type("18000")
	if err := tt.Click("delay-settings-save"); err != nil {
		t.Fatal(err)
	}
	if m.Prefs.DelayURL != "https://example.test/check" || m.Prefs.DelayTimeoutMS != 18000 || saved.DelayURL != m.Prefs.DelayURL || saved.DelayTimeoutMS != 18000 {
		t.Fatalf("settings were not applied and saved: %+v", m.Prefs)
	}
	if DelayText(12000, m.delayTimeoutMS()) != "12000" || ClassifySignal(12000, m.delayTimeoutMS()) != SignalHigh {
		t.Fatal("configured timeout was not used to classify a result")
	}
	for _, invalid := range []string{"", "file:///secret", "https://user:pass@example.test/", "https://example.test/#fragment", "https://exa\nmple.test/"} {
		m.delayURLDraft, m.delayTimeoutDraft = invalid, "3000"
		m.saveDelaySettings()
		if m.Prefs.DelayURL != "https://example.test/check" || m.Prefs.DelayTimeoutMS != 18000 {
			t.Fatalf("invalid URL changed settings: %q", invalid)
		}
	}
	for _, invalid := range []string{"0", "99", "60001", "not a number"} {
		m.delayURLDraft, m.delayTimeoutDraft = "https://example.test/", invalid
		m.saveDelaySettings()
		if m.Prefs.DelayTimeoutMS != 18000 {
			t.Fatalf("invalid timeout changed settings: %q", invalid)
		}
	}
	m.Hooks.SavePrefs = func(Prefs) error { return errors.New("settings conflict") }
	m.delayURLDraft, m.delayTimeoutDraft = "https://example.test/other", "3000"
	m.saveDelaySettings()
	if m.Prefs.DelayTimeoutMS != 18000 || m.Prefs.DelayURL != "https://example.test/check" || m.Notice != "settings conflict" {
		t.Fatal("failed persistence changed active settings")
	}
	m.Prefs.WebDAVPassword = "synthetic"
	m.Hooks.SavePrefs = func(Prefs) error { m.Prefs.WebDAVPassword = ""; return nil }
	m.saveDelaySettings()
	if m.Prefs.WebDAVPassword != "" || m.Prefs.DelayTimeoutMS != 3000 {
		t.Fatal("saving delay preferences undid another change made while saving")
	}
	m.Prefs.DelayURL, m.Prefs.DelayTimeoutMS = "file:///bad", 70000
	if m.delayURL() != defaultDelayURL || m.delayTimeoutMS() != DelayTimeout {
		t.Fatal("invalid persisted values did not fall back to safe defaults")
	}
}

func TestProxyColumnsAreSavedAndRolledBackOnError(t *testing.T) {
	m := NewModel(HomeState{})
	m.Dialogs.Misc = true
	var saved Prefs
	m.Hooks.SavePrefs = func(p Prefs) error { saved = p; return nil }
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("proxy-cols"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("3"); err != nil {
		t.Fatal(err)
	}
	if m.Prefs.ProxyColumns != 3 || saved.ProxyColumns != 3 {
		t.Fatalf("column preference not saved: %d / %d", m.Prefs.ProxyColumns, saved.ProxyColumns)
	}
	m.Hooks.SavePrefs = func(Prefs) error { return errors.New("settings conflict") }
	if err := tt.Click("proxy-cols"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("4"); err != nil {
		t.Fatal(err)
	}
	if m.Prefs.ProxyColumns != 3 || m.Notice != "settings conflict" {
		t.Fatal("failed column save was not rolled back")
	}
}

func TestDelayRequestsUseSettingsAndGroupOverride(t *testing.T) {
	m := NewModel(HomeState{})
	m.Prefs.DelayURL = "https://example.test/default"
	m.Prefs.DelayTimeoutMS = 2500
	var urls []string
	m.Hooks.TestProxyAsync = func(group, name, url string, timeout time.Duration, done func(int, error)) {
		if timeout != 2500*time.Millisecond {
			t.Fatalf("wrong timeout: %v", timeout)
		}
		urls = append(urls, url)
		done(42, nil)
	}
	m.testProxyDelay("group", "first", "")
	m.testProxyDelay("group", "second", "https://example.test/group")
	m.Groups = []ProxyGroup{{Name: "group", TestURL: "https://example.test/home"}}
	m.testProxyDelay("group", "third", "")
	if len(urls) != 3 || urls[0] != m.Prefs.DelayURL || urls[1] != "https://example.test/group" || urls[2] != "https://example.test/home" {
		t.Fatalf("wrong URL precedence: %v", urls)
	}
}
