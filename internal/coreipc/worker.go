// Package coreipc contains the kernel protocol. A caller must supply an already
// authenticated, private transport; it deliberately does not open a listener.
package coreipc

import (
	"errors"
	"io"
	"net/rpc"
	"path/filepath"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rules"
)

const MaxConfigBytes = 8 << 20
const maxLogs = 2048

type Empty struct{}
type Name struct{ Value string }
type Selection struct{ Group, Node string }
type Apply struct {
	Directory string
	Config    []byte
}
type Delay struct {
	Group, Node, URL string
	Timeout          time.Duration
}
type DelayResult struct{ Milliseconds int }
type BoolResult struct{ Value bool }
type TextResult struct{ Value string }
type ConfigResult struct{ Value []byte }
type Connections struct {
	Items            []conn.Item
	Upload, Download int64
}
type Rules struct{ Items []rules.Item }
type RuleProviders struct{ Items []rules.Provider }
type ProxyProviders struct{ Items []core.ProxyProvider }
type LogQuery struct{ After uint64 }
type LogLine struct {
	Sequence       uint64
	Level, Payload string
}
type Logs struct{ Items []LogLine }

// Worker serves exactly one private transport. When that transport closes, it
// tears down the kernel so a lost UI cannot leave an orphan TUN process.
type Worker struct {
	kernel   *core.Core
	applyMu  sync.Mutex
	logMu    sync.Mutex
	logs     []LogLine
	sequence uint64
	stopLogs func()
	home     string
	closed   bool
}

func NewWorker() *Worker {
	w := &Worker{kernel: core.New()}
	w.stopLogs = w.kernel.SubscribeLogs(func(level, payload string) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		w.logMu.Lock()
		defer w.logMu.Unlock()
		w.sequence++
		w.logs = append(w.logs, LogLine{Sequence: w.sequence, Level: level, Payload: payload})
		if len(w.logs) > maxLogs {
			copy(w.logs, w.logs[len(w.logs)-maxLogs:])
			w.logs = w.logs[:maxLogs]
		}
	})
	return w
}

type monitoredConn struct {
	io.ReadWriteCloser
	done chan struct{}
	once sync.Once
}

func (c *monitoredConn) signal(err error) {
	if err != nil {
		c.once.Do(func() { close(c.done) })
	}
}
func (c *monitoredConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	c.signal(err)
	return n, err
}
func (c *monitoredConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	c.signal(err)
	return n, err
}

func (w *Worker) Serve(c io.ReadWriteCloser) error {
	if c == nil {
		return errors.New("nil kernel transport")
	}
	s := rpc.NewServer()
	if err := s.RegisterName("Kernel", w); err != nil {
		return err
	}
	conn := &monitoredConn{ReadWriteCloser: c, done: make(chan struct{})}
	served := make(chan struct{})
	go func() { s.ServeConn(conn); close(served) }()
	// ServeConn waits for outstanding RPC handlers; the TUN must be stopped as
	// soon as the connection is lost, even if a network probe is still hung.
	select {
	case <-conn.done:
	case <-served:
	}
	_ = c.Close()
	w.applyMu.Lock()
	w.closed = true
	err := w.kernel.Stop()
	w.applyMu.Unlock()
	w.stopLogs()
	return err
}

func validConfig(b []byte) error {
	if len(b) == 0 || len(b) > MaxConfigBytes {
		return errors.New("invalid effective kernel configuration size")
	}
	return nil
}

func (w *Worker) Start(in Apply, out *Empty) error {
	if err := validConfig(in.Config); err != nil {
		return err
	}
	if !filepath.IsAbs(in.Directory) {
		return errors.New("kernel directory must be absolute")
	}
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	if w.closed {
		return errors.New("kernel transport closed")
	}
	if w.kernel.Status().Running {
		return errors.New("core already running")
	}
	dir := filepath.Clean(in.Directory)
	if w.home != "" && w.home != dir {
		return errors.New("worker cannot change its configuration directory")
	}
	w.home = dir
	// The UI's embedded kernel keeps its own cache open after Stop. A distinct
	// worker cache avoids lock conflicts without moving subscription files.
	C.SetCacheFile(filepath.Join(dir, "netflow-worker-cache.db"))
	b := append([]byte(nil), in.Config...)
	w.kernel.SetTransformer(func([]byte, string) ([]byte, error) { return b, nil })
	return w.kernel.Start(in.Directory)
}
func (w *Worker) Reload(in Apply, out *Empty) error {
	if err := validConfig(in.Config); err != nil {
		return err
	}
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	if w.closed {
		return errors.New("kernel transport closed")
	}
	b := append([]byte(nil), in.Config...)
	w.kernel.SetTransformer(func([]byte, string) ([]byte, error) { return b, nil })
	return w.kernel.Reload()
}
func (w *Worker) Stop(_ Empty, out *Empty) error {
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	return w.kernel.Stop()
}
func (w *Worker) Status(_ Empty, out *core.Status) error { *out = w.kernel.Status(); return nil }
func (w *Worker) EffectiveConfig(_ Empty, out *ConfigResult) (err error) {
	out.Value, err = w.kernel.EffectiveConfig()
	return
}
func (w *Worker) Select(in Selection, out *Empty) error { return w.kernel.Select(in.Group, in.Node) }
func (w *Worker) Selected(in Name, out *TextResult) (err error) {
	out.Value, err = w.kernel.Selected(in.Value)
	return
}
func (w *Worker) Group(in Name, out *core.ProxyGroup) (err error) {
	*out, err = w.kernel.Group(in.Value)
	return
}
func (w *Worker) Connections(_ Empty, out *Connections) error {
	out.Items, out.Upload, out.Download = w.kernel.Connections()
	return nil
}
func (w *Worker) CloseConnection(in Name, out *Empty) error {
	return w.kernel.CloseConnection(in.Value)
}
func (w *Worker) CloseExistingConnection(in Name, out *BoolResult) (err error) {
	out.Value, err = w.kernel.CloseExistingConnection(in.Value)
	return
}
func (w *Worker) CloseAllConnections(_ Empty, out *Empty) error {
	return w.kernel.CloseAllConnections()
}
func (w *Worker) Rules(_ Empty, out *Rules) error { out.Items = w.kernel.Rules(); return nil }
func (w *Worker) RuleProviders(_ Empty, out *RuleProviders) error {
	out.Items = w.kernel.RuleProviders()
	return nil
}
func (w *Worker) UpdateRuleProvider(in Name, out *Empty) error {
	return w.kernel.UpdateRuleProvider(in.Value)
}
func (w *Worker) ProxyProviders(_ Empty, out *ProxyProviders) error {
	out.Items = w.kernel.ProxyProviders()
	return nil
}
func (w *Worker) UpdateProxyProvider(in Name, out *Empty) error {
	return w.kernel.UpdateProxyProvider(in.Value)
}
func (w *Worker) TestDelay(in Delay, out *DelayResult) (err error) {
	out.Milliseconds, err = w.kernel.TestDelay(in.Group, in.Node, in.URL, in.Timeout)
	return
}
func (w *Worker) Logs(in LogQuery, out *Logs) error {
	w.logMu.Lock()
	defer w.logMu.Unlock()
	for _, v := range w.logs {
		if v.Sequence > in.After {
			out.Items = append(out.Items, v)
		}
	}
	return nil
}
