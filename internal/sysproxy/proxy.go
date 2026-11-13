// Package sysproxy sets the operating system proxy.
//
// Platform returns the macOS networksetup/scutil controller, or an
// in-memory controller on other systems. Tests pass their own Controller.
package sysproxy

import "sync"

// Settings is the proxy the app wants the system to use.
type Settings struct {
	Enabled bool
	HTTP    string
	SOCKS   string
}

// Controller reads and applies system proxy settings.
type Controller interface {
	Current() (Settings, error)
	Set(Settings) error
}

// Memory keeps settings in the process. It is the M1 placeholder and a
// fake for tests.
type Memory struct {
	mu  sync.Mutex
	cur Settings
	err error
}

// NewMemory returns a controller with the proxy disabled.
func NewMemory() *Memory { return &Memory{} }

// Fail makes the next Set return err. A nil err clears the failure.
func (m *Memory) Fail(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// Current returns the last settings applied.
func (m *Memory) Current() (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur, nil
}

// Set records s.
func (m *Memory) Set(s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.cur = s
	return nil
}
