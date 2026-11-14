// Package appconfig persists the app's own settings, apart from the
// mihomo profile.
package appconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/neko233-com/netflow/internal/safepath"
)

// Settings is what the app remembers between launches. Prefs is the
// settings page encoded as JSON so new fields do not need a migration.
type Settings struct {
	SystemProxy bool   `json:"systemProxy"`
	TUN         bool   `json:"tun"`
	TrayEvent   string `json:"trayEvent,omitempty"`
	InlineModes bool   `json:"inlineModes,omitempty"`
	ProxyMenu   string `json:"proxyMenu,omitempty"`
	Lightweight bool   `json:"lightweight,omitempty"`
	Prefs       string `json:"prefs,omitempty"`
}

// Store loads and saves Settings. Dir is the directory passed to the kernel.
type Store interface {
	Dir() string
	Load() (Settings, error)
	Save(Settings) error
}

// FileStore keeps settings.json inside a config directory.
type FileStore struct {
	dir string
}

// NewFileStore returns a store for dir. The directory is created on Save.
func NewFileStore(dir string) *FileStore { return &FileStore{dir: dir} }

// Dir returns the config directory.
func (s *FileStore) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Load returns zero settings when settings.json does not exist yet.
func (s *FileStore) Load() (Settings, error) {
	if s == nil || s.dir == "" {
		return Settings{}, errors.New("settings store has no directory")
	}
	b, err := safepath.ReadFile(s.dir, "settings.json")
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return Settings{}, nil
	}
	var out Settings
	if err := json.Unmarshal(b, &out); err != nil {
		return Settings{}, fmt.Errorf("decode settings: %w", err)
	}
	return out, nil
}

// Save writes settings.json, creating the directory when needed.
func (s *FileStore) Save(in Settings) error {
	if s == nil || s.dir == "" {
		return errors.New("settings store has no directory")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return safepath.WriteFile(s.dir, "settings.json", b)
}
