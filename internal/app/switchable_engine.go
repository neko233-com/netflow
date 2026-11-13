package app

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rules"
)

type engineLogSubscription struct {
	fn   func(string, string)
	stop func()
}

// switchableEngine serializes handoff between a desktop kernel and a private
// worker; readers cannot observe a half-switched engine.
type switchableEngine struct {
	mu        sync.RWMutex
	active    coreEngine
	transform func([]byte, string) ([]byte, error)
	nextLog   uint64
	logs      map[uint64]*engineLogSubscription
}

func newSwitchableEngine(active coreEngine) *switchableEngine {
	return &switchableEngine{active: active, logs: make(map[uint64]*engineLogSubscription)}
}
func (s *switchableEngine) SetTransformer(fn func([]byte, string) ([]byte, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transform = fn
	s.active.SetTransformer(fn)
}
func (s *switchableEngine) SetProfileID(id string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.active.SetProfileID(id)
}
func (s *switchableEngine) ProfileID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.ProfileID()
}
func (s *switchableEngine) Start(dir string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Start(dir)
}
func (s *switchableEngine) Reload() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Reload()
}
func (s *switchableEngine) Stop() error { s.mu.RLock(); defer s.mu.RUnlock(); return s.active.Stop() }
func (s *switchableEngine) Status() core.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Status()
}
func (s *switchableEngine) EffectiveConfig() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.EffectiveConfig()
}
func (s *switchableEngine) Select(g, n string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Select(g, n)
}
func (s *switchableEngine) Selected(g string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Selected(g)
}
func (s *switchableEngine) Connections() ([]conn.Item, int64, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Connections()
}
func (s *switchableEngine) CloseConnection(id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.CloseConnection(id)
}
func (s *switchableEngine) CloseExistingConnection(id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.CloseExistingConnection(id)
}
func (s *switchableEngine) CloseAllConnections() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.CloseAllConnections()
}
func (s *switchableEngine) Rules() []rules.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Rules()
}
func (s *switchableEngine) RuleProviders() []rules.Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.RuleProviders()
}
func (s *switchableEngine) UpdateRuleProvider(n string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.UpdateRuleProvider(n)
}
func (s *switchableEngine) Group(n string) (core.ProxyGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Group(n)
}
func (s *switchableEngine) ProxyProviders() []core.ProxyProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.ProxyProviders()
}
func (s *switchableEngine) UpdateProxyProvider(n string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.UpdateProxyProvider(n)
}
func (s *switchableEngine) TestDelay(g, n, u string, d time.Duration) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.TestDelay(g, n, u, d)
}
func (s *switchableEngine) SubscribeLogs(fn func(string, string)) func() {
	s.mu.Lock()
	s.nextLog++
	id := s.nextLog
	s.logs[id] = &engineLogSubscription{fn: fn, stop: s.active.SubscribeLogs(fn)}
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if sub := s.logs[id]; sub != nil {
				sub.stop()
				delete(s.logs, id)
			}
		})
	}
}
func (s *switchableEngine) stopLogs() {
	for _, sub := range s.logs {
		sub.stop()
	}
}
func (s *switchableEngine) startLogs() {
	for _, sub := range s.logs {
		sub.stop = s.active.SubscribeLogs(sub.fn)
	}
}

// replace is a transaction: if starting the new engine fails, undo the staged
// settings and restart the previous engine. before and undo run under the same
// lock as all engine calls and must not themselves call this wrapper.
func (s *switchableEngine) replace(next coreEngine, before func() error, commit func() error, undo func() error) error {
	if next == nil {
		return errors.New("new kernel is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switched := false
	defer func() {
		if !switched {
			if c, ok := next.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	}()
	old := s.active
	status := old.Status()
	if !status.Running || status.ConfigDir == "" {
		return errors.New("内核未运行，无法切换进程")
	}
	id := old.ProfileID()
	s.stopLogs()
	if err := old.Stop(); err != nil {
		s.startLogs()
		return err
	}
	rollback := func(cause error) error {
		stopErr := next.Stop()
		var closeErr error
		if c, ok := next.(interface{ Close() error }); ok {
			closeErr = c.Close()
		}
		var undoErr error
		if undo != nil {
			undoErr = undo()
		}
		if stopErr != nil || closeErr != nil {
			return errors.Join(cause, undoErr, fmt.Errorf("无法确认新内核已退出，原内核未重新启动: %w", errors.Join(stopErr, closeErr)))
		}
		restartErr := old.Start(status.ConfigDir)
		s.startLogs()
		if restartErr != nil {
			return errors.Join(cause, undoErr, fmt.Errorf("恢复原内核失败: %w", restartErr))
		}
		return errors.Join(cause, undoErr)
	}
	if before != nil {
		if err := before(); err != nil {
			return rollback(err)
		}
	}
	next.SetTransformer(s.transform)
	next.SetProfileID(id)
	if err := next.Start(status.ConfigDir); err != nil {
		return rollback(err)
	}
	if commit != nil {
		if err := commit(); err != nil {
			return rollback(err)
		}
	}
	s.active = next
	switched = true
	s.startLogs()
	if c, ok := old.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	return nil
}

var _ coreEngine = (*switchableEngine)(nil)
