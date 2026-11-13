package tun

import (
	"errors"
	"testing"
)

func TestPlatformStaysOffInCI(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("CLASHGO_TUN_LIVE", "1")
	if Platform().Available() {
		t.Fatal("CI allowed a TUN device")
	}
	if err := Platform().Set(true); err == nil {
		t.Fatal("CI Set(true) succeeded")
	}
}

func TestPlatformRefusesWithoutPrivilege(t *testing.T) {
	c := Platform()
	if c.Available() {
		t.Fatal("platform helper is available without CLASHGO_TUN_LIVE and root")
	}
	if err := c.Set(true); err == nil || err.Error() != ErrNeedService.Error() {
		t.Fatalf("Set(true) %v", err)
	}
	on, err := c.Current()
	if err != nil || on {
		t.Fatalf("current %v %v", on, err)
	}
}

func TestMemory(t *testing.T) {
	m := NewMemory()
	on, err := m.Current()
	if err != nil {
		t.Fatal(err)
	}
	if on {
		t.Fatal("TUN starts enabled")
	}
	if err := m.Set(true); err != nil {
		t.Fatal(err)
	}
	on, err = m.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("TUN did not turn on")
	}
	m.Fail(errors.New("denied"))
	if err := m.Set(false); err == nil {
		t.Fatal("Set succeeded after Fail")
	}
	on, _ = m.Current()
	if !on {
		t.Fatal("failed Set cleared TUN")
	}
}
