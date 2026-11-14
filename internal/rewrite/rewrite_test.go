package rewrite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestStorePreservesExternalChanges(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(map[bool]string{false: "created", true: "modified-or-deleted"}[initial], func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if initial {
				if _, err := s.Replace(State{Global: Layer{Prepend: []string{"DOMAIN,old.test,DIRECT"}}}, 0); err != nil {
					t.Fatal(err)
				}
			}
			original := s.Snapshot()
			path := filepath.Join(dir, "agent-rules.json")
			external := []byte("{\"revision\":77,\"global\":{},\"future_field\":true}\n")
			if err := os.WriteFile(path, external, 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckCurrent(); !errors.Is(err, ErrConflict) {
				t.Fatalf("check external change: %v", err)
			}
			if _, err := s.Replace(State{}, original.Revision); !errors.Is(err, ErrConflict) {
				t.Fatalf("replace external change: %v", err)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != string(external) {
				t.Fatalf("external file changed: %q %v", got, err)
			}
			if !reflect.DeepEqual(s.Snapshot(), original) {
				t.Fatal("in-memory state changed on conflict")
			}
			if initial {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := s.CheckCurrent(); !errors.Is(err, ErrConflict) {
					t.Fatalf("check deletion: %v", err)
				}
				if _, err := s.Replace(State{}, original.Revision); !errors.Is(err, ErrConflict) {
					t.Fatalf("replace deleted file: %v", err)
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("deleted file was recreated: %v", err)
				}
			}
		})
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

func TestHistoryIsBoundedPersistentAndIsolated(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 11; i++ {
		next := s.Snapshot()
		next.Global.Prepend = []string{fmt.Sprintf("DOMAIN,%d.test,DIRECT", i)}
		if _, err := s.Replace(next, i); err != nil {
			t.Fatal(err)
		}
	}
	history := s.History()
	if len(history) != maxHistoryEntries || history[0].Revision != 10 || history[len(history)-1].Revision != 3 {
		t.Fatalf("unexpected history: %+v", history)
	}
	old, err := s.Historical(3)
	if err != nil || old.Global.Prepend[0] != "DOMAIN,2.test,DIRECT" {
		t.Fatalf("old state: %+v %v", old, err)
	}
	old.Global.Prepend[0] = "mutated"
	old, err = s.Historical(3)
	if err != nil || old.Global.Prepend[0] == "mutated" {
		t.Fatal("history state was not isolated")
	}
	if _, err := s.Historical(2); err == nil {
		t.Fatal("evicted revision remained available")
	}
	reopened, err := Open(dir)
	if err != nil || !reflect.DeepEqual(reopened.History(), history) {
		t.Fatalf("history was not persisted: %v", err)
	}
}

func TestClearHistoryPreservesRulesAndRejectsExternalChange(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.Replace(State{Global: Layer{Prepend: []string{"DOMAIN,keep.test,DIRECT"}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-rules.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("external edit"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClearHistory(); !errors.Is(err, ErrConflict) {
		t.Fatalf("external edit accepted: %v", err)
	}
	if len(s.History()) != 1 || !reflect.DeepEqual(s.Snapshot(), state) {
		t.Fatal("failed clear modified memory")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	revision, err := s.ClearHistory()
	if err != nil || revision != state.Revision+1 {
		t.Fatalf("clear: %d %v", revision, err)
	}
	state.Revision = revision
	reopened, err := Open(dir)
	if err != nil || len(reopened.History()) != 0 || !reflect.DeepEqual(reopened.Snapshot(), state) {
		t.Fatalf("clear not persisted: %v", err)
	}
	if again, err := reopened.ClearHistory(); err != nil || again != revision {
		t.Fatalf("empty clear changed revision: %d %v", again, err)
	}
}

func TestHistoryPrunesToFileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		state := s.Snapshot()
		state.Global.Prepend = make([]string, 400)
		for j := range state.Global.Prepend {
			state.Global.Prepend[j] = fmt.Sprintf("DOMAIN,%d-%d.%s,DIRECT", i, j, strings.Repeat("x", 3960))
		}
		if _, err := s.Replace(state, state.Revision); err != nil {
			t.Fatal(err)
		}
	}
	if history := s.History(); len(history) != 1 || history[0].Revision != 2 {
		t.Fatalf("size limit did not evict older states: %+v", history)
	}
	info, err := os.Stat(filepath.Join(dir, "agent-rules.json"))
	if err != nil || info.Size() > 4<<20 {
		t.Fatalf("oversized rewrite file: %v", err)
	}
	if reopened, err := Open(dir); err != nil || reopened.Snapshot().Revision != 3 {
		t.Fatalf("reopen pruned history: %v", err)
	}
}
