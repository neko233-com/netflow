// Package appconfig persists the app's own settings, apart from the
// mihomo profile.
package appconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"

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

var knownSettingsFields = func() []string {
	fields := make([]string, 0, reflect.TypeOf(Settings{}).NumField())
	typ := reflect.TypeOf(Settings{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}()

// Store loads and saves Settings. Dir is the directory passed to the kernel.
type Store interface {
	Dir() string
	Load() (Settings, error)
	Save(Settings) error
}

// FileStore keeps settings.json inside a config directory.
type FileStore struct {
	dir    string
	mu     sync.Mutex
	loaded bool
	raw    []byte // nil means settings.json was absent
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *FileStore) loadLocked() (Settings, error) {
	b, err := safepath.ReadFile(s.dir, "settings.json")
	if errors.Is(err, os.ErrNotExist) {
		s.loaded, s.raw = true, nil
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	if len(bytes.TrimSpace(b)) != 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			return Settings{}, fmt.Errorf("decode settings: %w", err)
		}
	}
	s.loaded = true
	s.raw = make([]byte, len(b))
	copy(s.raw, b)
	return out, nil
}

// Save preserves unknown fields and refuses to overwrite changes made since
// Load or the previous successful Save. A caller can explicitly reload.
func (s *FileStore) Save(in Settings) error {
	if s == nil || s.dir == "" {
		return errors.New("settings store has no directory")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if !s.loaded {
		if _, err := s.loadLocked(); err != nil {
			return err
		}
	}
	fields := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(s.raw)) != 0 {
		if err := json.Unmarshal(s.raw, &fields); err != nil {
			return fmt.Errorf("decode settings: %w", err)
		}
		if fields == nil {
			fields = map[string]json.RawMessage{}
		}
	}
	for key := range fields {
		for _, known := range knownSettingsFields {
			if strings.EqualFold(key, known) {
				delete(fields, key)
				break
			}
		}
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		return err
	}
	var updates map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &updates); err != nil {
		return err
	}
	for key, value := range updates {
		fields[key] = value
	}
	b, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := safepath.CompareAndWrite(s.dir, "settings.json", s.raw, b); err != nil {
		if errors.Is(err, safepath.ErrChanged) {
			return fmt.Errorf("settings changed outside NetFlow; inspect and restart: %w", err)
		}
		return err
	}
	s.raw = append([]byte(nil), b...)
	return nil
}
