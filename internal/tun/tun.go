// Package tun enables the kernel's TUN interface.
//
// The M1 controller only remembers the switch. Opening a real TUN device
// is a later milestone, and tests that do so use the integration build tag.
package tun

import "sync"

// Controller reads and sets whether TUN is enabled.
// Available is false when turning it on must be refused (no helper, or CI).
type Controller interface {
	Current() (bool, error)
	Set(enabled bool) error
	Available() bool
}

// Memory remembers the switch in the process.
type Memory struct {
	mu  sync.Mutex
	on  bool
	err error
}

// NewMemory returns a controller with TUN off.
func NewMemory() *Memory { return &Memory{} }

// Fail makes the next Set return err.
func (m *Memory) Fail(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// Current reports the remembered switch.
func (m *Memory) Current() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.on, nil
}

// Available reports that the in-memory switch may change.
// It does not open a device.
func (m *Memory) Available() bool { return true }

// Set records enabled.
func (m *Memory) Set(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.on = enabled
	return nil
}
