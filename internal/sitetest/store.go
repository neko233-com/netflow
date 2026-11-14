// Package sitetest stores the website test list (name, URL, icon).
package sitetest

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/neko233-com/netflow/internal/safepath"
)

// Item is one saved test. Delay is not persisted; it is a session result.
type Item struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon,omitempty"`
}

// Store reads tests.json in a config directory.
type Store struct {
	dir string
}

// NewStore returns a store for dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Load returns nil when the file is missing.
func (s *Store) Load() ([]Item, error) {
	if s == nil || s.dir == "" {
		return nil, errors.New("test store has no directory")
	}
	b, err := safepath.ReadFile(s.dir, "tests.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// Save writes the list. Nil becomes an empty list.
func (s *Store) Save(items []Item) error {
	if s == nil || s.dir == "" {
		return errors.New("test store has no directory")
	}
	if items == nil {
		items = []Item{}
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return safepath.WriteFile(s.dir, "tests.json", b)
}
