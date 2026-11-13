package appconfig

import "errors"

// Memory is an in-memory Store for tests.
type Memory struct {
	dir      string
	settings Settings
	loadErr  error
	saveErr  error
}

// NewMemory returns an empty store whose Dir is dir.
func NewMemory(dir string) *Memory { return &Memory{dir: dir} }

// FailLoad makes the next Load return err.
func (m *Memory) FailLoad(err error) { m.loadErr = err }

// FailSave makes the next Save return err.
func (m *Memory) FailSave(err error) { m.saveErr = err }

// Dir returns the configured directory.
func (m *Memory) Dir() string { return m.dir }

// Load returns the saved settings.
func (m *Memory) Load() (Settings, error) {
	if m.loadErr != nil {
		return Settings{}, m.loadErr
	}
	return m.settings, nil
}

// Save replaces the saved settings.
func (m *Memory) Save(in Settings) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if m.dir == "" {
		return errors.New("settings store has no directory")
	}
	m.settings = in
	return nil
}
