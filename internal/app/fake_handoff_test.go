package app

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	mihomodns "github.com/metacubex/mihomo/dns"
)

type fakeStateEngine struct {
	*switchTestEngine
	state     *mihomodns.FakeIPState
	exportErr error
	staged    bool
}

func (e *fakeStateEngine) ExportFakeIPState() (*mihomodns.FakeIPState, error) {
	if e.running {
		return nil, errors.New("export occurred before stop")
	}
	return e.state, e.exportErr
}
func (e *fakeStateEngine) StageFakeIPState(state *mihomodns.FakeIPState) error {
	if e.running {
		return errors.New("stage occurred after start")
	}
	e.state, e.staged = state, true
	return nil
}

func TestSwitchTransfersFakeIPBeforeStartingNextKernel(t *testing.T) {
	state := &mihomodns.FakeIPState{IPv4: &fakeip.Snapshot{Prefix: "198.18.0.1/16", Offset: "198.18.0.4"}}
	old := &fakeStateEngine{switchTestEngine: &switchTestEngine{running: true, dir: t.TempDir()}, state: state}
	next := &fakeStateEngine{switchTestEngine: &switchTestEngine{}}
	next.onStart = func() {
		if !next.staged || next.state != state {
			t.Error("next kernel started without the snapshot")
		}
	}
	s := newSwitchableEngine(old)
	if err := s.replace(next, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !next.running || !old.closed {
		t.Fatal("kernel switch did not complete")
	}
}

func TestSwitchRollsBackWhenFakeIPExportFails(t *testing.T) {
	old := &fakeStateEngine{switchTestEngine: &switchTestEngine{running: true, dir: t.TempDir()}, exportErr: errors.New("snapshot failed")}
	next := &fakeStateEngine{switchTestEngine: &switchTestEngine{}}
	s := newSwitchableEngine(old)
	if err := s.replace(next, nil, nil, nil); err == nil {
		t.Fatal("failed export did not abort the switch")
	}
	if !old.running || next.running || !next.closed {
		t.Fatal("failed export did not restore the previous kernel")
	}
}
