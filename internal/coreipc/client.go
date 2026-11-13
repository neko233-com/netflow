package coreipc

import (
	"errors"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rules"
)

// Client is an engine over a private authenticated connection. It never opens
// a device itself. The application supplies the transport after validation.
type Client struct {
	rpc          *rpc.Client
	mu           sync.Mutex
	applyMu      sync.Mutex
	profileID    string
	dir          string
	transform    func([]byte, string) ([]byte, error)
	transportErr error
	closeOnce    sync.Once
	closeHook    func() error
	closeErr     error
}

func NewClient(c io.ReadWriteCloser) (*Client, error) {
	if c == nil {
		return nil, errors.New("nil kernel transport")
	}
	return &Client{rpc: rpc.NewClient(c)}, nil
}
func (c *Client) Close() error          { return c.rpc.Close() }
func (c *Client) TransportError() error { c.mu.Lock(); defer c.mu.Unlock(); return c.transportErr }
func (c *Client) call(method string, in, out any, timeout time.Duration) error {
	done := c.rpc.Go("Kernel."+method, in, out, make(chan *rpc.Call, 1)).Done
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		if result.Error != nil {
			var remote rpc.ServerError
			if !errors.As(result.Error, &remote) {
				c.mu.Lock()
				c.transportErr = result.Error
				c.mu.Unlock()
			}
		}
		return result.Error
	case <-timer.C:
		err := fmt.Errorf("kernel %s timed out", method)
		c.mu.Lock()
		c.transportErr = err
		c.mu.Unlock()
		_ = c.Close()
		return err
	}
}
func (c *Client) short(method string, in, out any) error {
	return c.call(method, in, out, 15*time.Second)
}
func (c *Client) SetTransformer(fn func([]byte, string) ([]byte, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.transform = fn
}
func (c *Client) SetProfileID(id string) { c.mu.Lock(); defer c.mu.Unlock(); c.profileID = id }
func (c *Client) ProfileID() string      { c.mu.Lock(); defer c.mu.Unlock(); return c.profileID }
func (c *Client) compose(dir string) ([]byte, error) {
	if dir == "" {
		return nil, errors.New("empty config directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "config.yaml")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = io.WriteString(file, core.DefaultConfig)
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if err := validConfig(data); err != nil {
		return nil, err
	}
	c.mu.Lock()
	fn, id := c.transform, c.profileID
	c.mu.Unlock()
	if fn != nil {
		data, err = fn(data, id)
		if err != nil {
			return nil, err
		}
	}
	if err := validConfig(data); err != nil {
		return nil, err
	}
	return data, nil
}
func (c *Client) Start(dir string) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	data, err := c.compose(dir)
	if err != nil {
		return err
	}
	if err := c.short("Start", Apply{Directory: dir, Config: data}, &Empty{}); err != nil {
		return err
	}
	c.mu.Lock()
	c.dir = dir
	c.mu.Unlock()
	return nil
}
func (c *Client) Reload() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	dir := c.dir
	c.mu.Unlock()
	if dir == "" {
		return errors.New("core is not running")
	}
	data, err := c.compose(dir)
	if err != nil {
		return err
	}
	return c.short("Reload", Apply{Config: data}, &Empty{})
}
func (c *Client) Stop() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	return c.short("Stop", Empty{}, &Empty{})
}
func (c *Client) EffectiveConfig() ([]byte, error) {
	var out ConfigResult
	err := c.short("EffectiveConfig", Empty{}, &out)
	return out.Value, err
}
func (c *Client) Status() core.Status {
	var out core.Status
	if err := c.short("Status", Empty{}, &out); err != nil {
		out.Version = core.Version()
		out.Error = "内核通信中断: " + err.Error()
	}
	return out
}
func (c *Client) Select(group, node string) error {
	return c.short("Select", Selection{group, node}, &Empty{})
}
func (c *Client) Selected(group string) (string, error) {
	var out TextResult
	err := c.short("Selected", Name{group}, &out)
	return out.Value, err
}
func (c *Client) Group(name string) (core.ProxyGroup, error) {
	var out core.ProxyGroup
	err := c.short("Group", Name{name}, &out)
	return out, err
}
func (c *Client) Connections() ([]conn.Item, int64, int64) {
	var out Connections
	_ = c.short("Connections", Empty{}, &out)
	return out.Items, out.Upload, out.Download
}
func (c *Client) CloseConnection(id string) error {
	return c.short("CloseConnection", Name{id}, &Empty{})
}
func (c *Client) CloseExistingConnection(id string) (bool, error) {
	var out BoolResult
	err := c.short("CloseExistingConnection", Name{id}, &out)
	return out.Value, err
}
func (c *Client) CloseAllConnections() error {
	return c.short("CloseAllConnections", Empty{}, &Empty{})
}
func (c *Client) Rules() []rules.Item {
	var out Rules
	_ = c.short("Rules", Empty{}, &out)
	return out.Items
}
func (c *Client) RuleProviders() []rules.Provider {
	var out RuleProviders
	_ = c.short("RuleProviders", Empty{}, &out)
	return out.Items
}
func (c *Client) UpdateRuleProvider(name string) error {
	return c.call("UpdateRuleProvider", Name{name}, &Empty{}, 2*time.Minute)
}
func (c *Client) ProxyProviders() []core.ProxyProvider {
	var out ProxyProviders
	_ = c.short("ProxyProviders", Empty{}, &out)
	return out.Items
}
func (c *Client) UpdateProxyProvider(name string) error {
	return c.call("UpdateProxyProvider", Name{name}, &Empty{}, 2*time.Minute)
}
func (c *Client) TestDelay(group, node, url string, timeout time.Duration) (int, error) {
	var out DelayResult
	if timeout <= 0 || timeout > time.Minute {
		return 0, errors.New("测速超时时间无效")
	}
	err := c.call("TestDelay", Delay{group, node, url, timeout}, &out, timeout+15*time.Second)
	return out.Milliseconds, err
}
func (c *Client) SubscribeLogs(fn func(string, string)) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint64
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var out Logs
				if c.short("Logs", LogQuery{sequence}, &out) != nil {
					return
				}
				for _, line := range out.Items {
					sequence = line.Sequence
					if fn != nil {
						fn(line.Level, line.Payload)
					}
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}
