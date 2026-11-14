package rewrite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/neko233-com/netflow/internal/safepath"
)

var ErrConflict = errors.New("rewrite revision changed; preview again")

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("empty rewrite directory")
	}
	s := &Store{path: filepath.Join(dir, "agent-rules.json")}
	data, err := safepath.ReadFileLimit(dir, "agent-rules.json", 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, errors.New("rewrite state is too large")
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("read rewrite state: %w", err)
	}
	if err := s.state.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func clone(s State) State {
	data, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(data, &out)
	return out
}

func (s *Store) Snapshot() State { s.mu.RLock(); defer s.mu.RUnlock(); return clone(s.state) }

// Replace atomically persists an optimistic revision; failed writes keep the
// in-memory state unchanged. The returned state has the new revision.
func (s *Store) Replace(next State, expected uint64) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Revision != expected {
		return State{}, ErrConflict
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	next.Revision = expected + 1
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return State{}, err
	}
	if len(data) > 4<<20 {
		return State{}, errors.New("rewrite state is too large")
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return State{}, err
	}
	if err = safepath.WriteFile(filepath.Dir(s.path), filepath.Base(s.path), append(data, '\n')); err != nil {
		return State{}, err
	}
	s.state = clone(next)
	return clone(s.state), nil
}
