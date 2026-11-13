package sysproxy

import (
	"errors"
	"testing"
)

func TestMemory(t *testing.T) {
	m := NewMemory()
	cur, err := m.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cur.Enabled {
		t.Fatal("proxy starts enabled")
	}
	want := Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}
	if err := m.Set(want); err != nil {
		t.Fatal(err)
	}
	cur, err = m.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cur != want {
		t.Fatalf("current %+v, want %+v", cur, want)
	}
	m.Fail(errors.New("denied"))
	if err := m.Set(Settings{}); err == nil {
		t.Fatal("Set succeeded after Fail")
	}
	cur, _ = m.Current()
	if cur != want {
		t.Fatalf("failed Set changed settings to %+v", cur)
	}
}
