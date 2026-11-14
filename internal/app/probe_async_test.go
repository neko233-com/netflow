package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/ui"
)

type delayCaptureEngine struct {
	coreEngine
	request chan time.Duration
}

func TestDelayPreferencesPersistToSettingsFile(t *testing.T) {
	dir := t.TempDir()
	store := appconfig.NewFileStore(dir)
	settings, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store, settings: settings}
	p := ui.DefaultPrefs()
	p.DelayURL, p.DelayTimeoutMS, p.ProxyColumns = "https://example.test/probe", 23000, 3
	if err := a.savePrefs(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := appconfig.NewFileStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	got := ui.DefaultPrefs()
	if err := json.Unmarshal([]byte(loaded.Prefs), &got); err != nil {
		t.Fatal(err)
	}
	if got.DelayURL != p.DelayURL || got.DelayTimeoutMS != p.DelayTimeoutMS || got.ProxyColumns != p.ProxyColumns {
		t.Fatalf("settings did not survive reload: %+v", got)
	}
}

func (e delayCaptureEngine) TestDelay(group, node, url string, timeout time.Duration) (int, error) {
	e.request <- timeout
	return 42, nil
}

func TestAsyncDelayPassesConfiguredTimeout(t *testing.T) {
	request := make(chan time.Duration, 1)
	a := &App{core: delayCaptureEngine{request: request}, probeSlots: make(chan struct{}, 1), probeStop: make(chan struct{}), dispatch: func(f func()) { f() }}
	completed := make(chan int, 1)
	a.testProxyAsync("group", "node", "https://example.test/", 2500*time.Millisecond, func(ms int, err error) {
		if err != nil {
			completed <- -1
			return
		}
		completed <- ms
	})
	select {
	case got := <-request:
		if got != 2500*time.Millisecond {
			t.Fatalf("wrong core timeout: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not run")
	}
	select {
	case got := <-completed:
		if got != 42 {
			t.Fatalf("wrong result: %d", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not complete")
	}
}
