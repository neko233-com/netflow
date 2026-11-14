package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestGeoUpdateReportsRestartAndFailure(t *testing.T) {
	m := NewModel(HomeState{})
	var finish func(int, error)
	m.Hooks.UpdateGeoAsync = func(done func(int, error)) { finish = done }
	m.updateGeo()
	if m.Busy != "geo" || finish == nil {
		t.Fatal("update was not started")
	}
	finish(2, nil)
	if m.Busy != "" || !strings.Contains(m.Notice, "重新启动") {
		t.Fatalf("notice: %s", m.Notice)
	}
	m.updateGeo()
	finish(0, errors.New("network"))
	if m.Busy != "" || !strings.Contains(m.Notice, "失败") {
		t.Fatalf("failure: %s", m.Notice)
	}
}
