package rewrite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neko233-com/netflow/internal/safepath"
)

var ErrConflict = errors.New("rewrite state changed")

func externalConflict() error {
	return fmt.Errorf("%w: rules file changed outside NetFlow; inspect it and restart", ErrConflict)
}

type Store struct {
	mu      sync.RWMutex
	path    string
	state   State
	raw     []byte // exact on-disk contents; nil means the file was absent
	history []historyEntry
}

const maxHistoryEntries = 8

type HistoryItem struct {
	Revision   uint64    `json:"revision"`
	RecordedAt time.Time `json:"recorded_at"`
}

type historyEntry struct {
	HistoryItem
	State State `json:"state"`
}

type persistedState struct {
	State
	History []historyEntry `json:"history,omitempty"`
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
	var saved persistedState
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("read rewrite state: %w", err)
	}
	if err := saved.State.Validate(); err != nil {
		return nil, err
	}
	if len(saved.History) > maxHistoryEntries {
		return nil, errors.New("too many rewrite history entries")
	}
	seen := make(map[uint64]bool)
	for _, entry := range saved.History {
		if entry.RecordedAt.IsZero() || entry.Revision != entry.State.Revision || entry.Revision >= saved.State.Revision || seen[entry.Revision] {
			return nil, errors.New("invalid rewrite history entry")
		}
		if err := entry.State.Validate(); err != nil {
			return nil, fmt.Errorf("invalid rewrite history: %w", err)
		}
		seen[entry.Revision] = true
	}
	s.state, s.history = saved.State, saved.History
	s.raw = data
	return s, nil
}

func clone(s State) State {
	data, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(data, &out)
	return out
}

func (s *Store) Snapshot() State { s.mu.RLock(); defer s.mu.RUnlock(); return clone(s.state) }

// History returns summaries newest first; actual rules are only exposed after a
// caller requests a validated preview of a specific scope and revision.
func (s *Store) History() []HistoryItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]HistoryItem, 0, len(s.history))
	for i := len(s.history) - 1; i >= 0; i-- {
		items = append(items, s.history[i].HistoryItem)
	}
	return items
}

func (s *Store) Historical(revision uint64) (State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.history {
		if entry.Revision == revision {
			return clone(entry.State), nil
		}
	}
	return State{}, errors.New("rewrite history revision not found")
}

// ClearHistory removes stored snapshots without changing active rules. A new
// revision invalidates outstanding proposals based on those snapshots.
func (s *Store) ClearHistory() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) == 0 {
		return s.state.Revision, nil
	}
	if s.state.Revision == math.MaxUint64 {
		return 0, errors.New("rewrite revision exhausted")
	}
	next := clone(s.state)
	next.Revision++
	data, err := json.MarshalIndent(persistedState{State: next}, "", "  ")
	if err != nil {
		return 0, err
	}
	data = append(data, '\n')
	if err := safepath.CompareAndWrite(filepath.Dir(s.path), filepath.Base(s.path), s.raw, data); err != nil {
		if errors.Is(err, safepath.ErrChanged) {
			return 0, externalConflict()
		}
		return 0, err
	}
	s.state, s.raw, s.history = next, data, nil
	return next.Revision, nil
}

// CheckCurrent rejects an external modification instead of silently presenting
// stale in-memory rules as the current disk state. Restarting reopens the file.
func (s *Store) CheckCurrent() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := safepath.ReadFileLimit(filepath.Dir(s.path), filepath.Base(s.path), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		if s.raw == nil {
			return nil
		}
		return externalConflict()
	}
	if err != nil {
		return err
	}
	if s.raw == nil || !bytes.Equal(data, s.raw) {
		return externalConflict()
	}
	return nil
}

// Replace atomically persists an optimistic revision; failed writes keep the
// in-memory state unchanged. The returned state has the new revision.
func (s *Store) Replace(next State, expected uint64) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Revision != expected {
		return State{}, fmt.Errorf("%w: preview again", ErrConflict)
	}
	if expected == math.MaxUint64 {
		return State{}, errors.New("rewrite revision exhausted")
	}
	if err := next.Validate(); err != nil {
		return State{}, err
	}
	next.Revision = expected + 1
	history := append(append([]historyEntry(nil), s.history...), historyEntry{HistoryItem: HistoryItem{Revision: expected, RecordedAt: time.Now().UTC()}, State: clone(s.state)})
	if len(history) > maxHistoryEntries {
		history = history[len(history)-maxHistoryEntries:]
	}
	var data []byte
	var err error
	for {
		data, err = json.MarshalIndent(persistedState{State: next, History: history}, "", "  ")
		if err != nil {
			return State{}, err
		}
		if len(data)+1 <= 4<<20 {
			break
		}
		if len(history) == 0 {
			return State{}, errors.New("rewrite state is too large")
		}
		history = history[1:]
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return State{}, err
	}
	data = append(data, '\n')
	if err = safepath.CompareAndWrite(filepath.Dir(s.path), filepath.Base(s.path), s.raw, data); err != nil {
		if errors.Is(err, safepath.ErrChanged) {
			return State{}, externalConflict()
		}
		return State{}, err
	}
	s.state = clone(next)
	s.raw = data
	s.history = history
	return clone(s.state), nil
}
