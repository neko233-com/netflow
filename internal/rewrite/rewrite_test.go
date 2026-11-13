package rewrite

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestComposePriorityAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := []byte("mixed-port: 1234\nrules:\n  - DOMAIN,remove.test,DIRECT\n  - DOMAIN,base.test,DIRECT\n  - MATCH,DIRECT\n")
	s := State{Global: Layer{Prepend: []string{"DOMAIN,global.test,DIRECT"}, Append: []string{"DOMAIN,global-end.test,DIRECT"}, Remove: []string{"DOMAIN,remove.test,DIRECT"}}, Profiles: map[string]Layer{"p1": {Prepend: []string{"DOMAIN,profile.test,DIRECT"}, Append: []string{"DOMAIN,profile-end.test,DIRECT"}}}, Connections: []Connection{{ID: "expired", ProfileID: "p1", Rule: "DOMAIN,expired.test,DIRECT", ExpiresAt: now}, {ID: "live", ProfileID: "p1", Rule: "DOMAIN,live.test,DIRECT", ExpiresAt: now.Add(time.Minute)}, {ID: "other", ProfileID: "p2", Rule: "DOMAIN,other.test,DIRECT", ExpiresAt: now.Add(time.Minute)}}}
	_, got, err := Compose(base, s, "p1", now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DOMAIN,live.test,DIRECT", "DOMAIN,profile.test,DIRECT", "DOMAIN,global.test,DIRECT", "DOMAIN,base.test,DIRECT", "DOMAIN,profile-end.test,DIRECT", "DOMAIN,global-end.test,DIRECT", "MATCH,DIRECT"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules: %#v", got)
	}
	if string(base) != "mixed-port: 1234\nrules:\n  - DOMAIN,remove.test,DIRECT\n  - DOMAIN,base.test,DIRECT\n  - MATCH,DIRECT\n" {
		t.Fatal("base was modified")
	}
}

func TestStorePersistsAndRejectsStaleRevision(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Replace(State{Global: Layer{Prepend: []string{"DOMAIN,a.test,DIRECT"}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 {
		t.Fatal(first.Revision)
	}
	first.Global.Prepend[0] = "changed"
	if s.Snapshot().Global.Prepend[0] == "changed" {
		t.Fatal("returned mutable store data")
	}
	if _, err := s.Replace(State{}, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write: %v", err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Snapshot().Revision != 1 || again.Snapshot().Global.Prepend[0] != "DOMAIN,a.test,DIRECT" {
		t.Fatal(again.Snapshot())
	}
}
