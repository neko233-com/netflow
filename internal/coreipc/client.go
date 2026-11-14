package coreipc

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/rpc"
	"os"
	"sync"
	"time"

	mihomodns "github.com/metacubex/mihomo/dns"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rules"
	"github.com/neko233-com/netflow/internal/safepath"
)

// Client is an engine over a private authenticated connection. It never opens
// a device itself. The application supplies the transport after validation.
type Client struct {
	rpc           *rpc.Client
	mu            sync.Mutex
	applyMu       sync.Mutex
	profileID     string
	dir           string
	transform     func([]byte, string) ([]byte, error)
	transportErr  error
	closeOnce     sync.Once
	closeHook     func() error
	closeErr      error
	workerPID     uint32
	failureDetail func() error
	caches        cacheState
	cacheWarning  string
	cachePending  bool
	cacheStop     chan struct{}
	cacheLoopOnce sync.Once
	cacheInterval time.Duration
}

func NewClient(c io.ReadWriteCloser) (*Client, error) {
	if c == nil {
		return nil, errors.New("nil kernel transport")
	}
	return &Client{rpc: rpc.NewClient(c), cacheStop: make(chan struct{}), cacheInterval: 30 * time.Second}, nil
}
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.cacheStop)
		c.closeErr = c.rpc.Close()
		if c.closeHook != nil {
			c.closeErr = errors.Join(c.closeErr, c.closeHook())
		}
	})
	return c.closeErr
}
func (c *Client) TransportError() error { c.mu.Lock(); defer c.mu.Unlock(); return c.transportErr }
func (c *Client) WorkerPID() uint32     { return c.workerPID }
func (c *Client) call(method string, in, out any, timeout time.Duration) error {
	done := c.rpc.Go("Kernel."+method, in, out, make(chan *rpc.Call, 1)).Done
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		err := result.Error
		if err != nil {
			var remote rpc.ServerError
			if !errors.As(err, &remote) {
				if c.failureDetail != nil {
					err = errors.Join(err, c.failureDetail())
				}
				c.mu.Lock()
				c.transportErr = err
				c.mu.Unlock()
			}
		}
		return err
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
	file, err := safepath.CreateExclusive(dir, "config.yaml", []byte(core.DefaultConfig), false)
	if err == nil {
		err = file.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	data, err := safepath.ReadFileLimit(dir, "config.yaml", MaxConfigBytes)
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
	var capabilities Capabilities
	if err := c.short("Capabilities", Empty{}, &capabilities); err != nil {
		return err
	}
	var files []StageFile
	if capabilities.IsolatedFiles {
		files, err = snapshotDirectory(dir)
		if err != nil {
			return err
		}
	}
	if err := c.call("Start", Apply{Directory: dir, Config: data, Files: files}, &Empty{}, 45*time.Second); err != nil {
		return err
	}
	c.mu.Lock()
	c.dir = dir
	c.mu.Unlock()
	c.caches = newCacheState(files, capabilities.IsolatedFiles)
	if capabilities.IsolatedFiles {
		c.startCacheLoop()
	}
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
	var capabilities Capabilities
	if err := c.short("Capabilities", Empty{}, &capabilities); err != nil {
		return err
	}
	var files []StageFile
	if capabilities.IsolatedFiles {
		files, err = snapshotDirectory(dir)
		if err != nil {
			return err
		}
	}
	if err := c.call("Reload", Apply{Config: data, Files: files}, &Empty{}, 45*time.Second); err != nil {
		return err
	}
	c.caches = newCacheState(files, capabilities.IsolatedFiles)
	return nil
}
func (c *Client) Stop() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	var caches ProviderCaches
	if err := c.call("Stop", c.cacheQuery(), &caches, 45*time.Second); err != nil {
		return err
	}
	if c.caches.running && c.caches.isolated {
		if err := c.applyProviderCaches(caches); err != nil {
			log.Printf("provider cache was not persisted: %v", err)
		}
	}
	c.caches.running = false
	return nil
}
func (c *Client) EffectiveConfig() ([]byte, error) {
	var out ConfigResult
	err := c.short("EffectiveConfig", Empty{}, &out)
	return out.Value, err
}
func (c *Client) StageDirectory() (string, error) {
	var out TextResult
	err := c.short("StageDirectory", Empty{}, &out)
	return out.Value, err
}
func (c *Client) CleanedStages() ([]string, error) {
	var out TextListResult
	err := c.short("CleanedStages", Empty{}, &out)
	return out.Values, err
}
func (c *Client) ExportFakeIPState() (*mihomodns.FakeIPState, error) {
	var out FakeIPStateResult
	err := c.call("ExportFakeIPState", Empty{}, &out, 45*time.Second)
	return out.State, err
}
func (c *Client) StageFakeIPState(state *mihomodns.FakeIPState) error {
	return c.call("StageFakeIPState", FakeIPStateResult{State: state}, &Empty{}, 45*time.Second)
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
	return c.updateRuleProvider(name, nil)
}
func (c *Client) UpdateRuleProviderForProfile(name, profileID string) error {
	return c.updateRuleProvider(name, &profileID)
}
func (c *Client) updateRuleProvider(name string, expected *string) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if expected != nil && c.ProfileID() != *expected {
		return core.ErrProviderProfileChanged
	}
	if err := c.call("UpdateRuleProvider", Name{name}, &Empty{}, 2*time.Minute); err != nil {
		return err
	}
	if err := c.syncProviderCaches(); err != nil {
		return fmt.Errorf("%w: %v", ErrProviderCacheSync, err)
	}
	return nil
}
func (c *Client) ProxyProviders() []core.ProxyProvider {
	var out ProxyProviders
	_ = c.short("ProxyProviders", Empty{}, &out)
	return out.Items
}
func (c *Client) UpdateProxyProvider(name string) error {
	return c.updateProxyProvider(name, nil)
}
func (c *Client) UpdateProxyProviderForProfile(name, profileID string) error {
	return c.updateProxyProvider(name, &profileID)
}
func (c *Client) updateProxyProvider(name string, expected *string) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if expected != nil && c.ProfileID() != *expected {
		return core.ErrProviderProfileChanged
	}
	if err := c.call("UpdateProxyProvider", Name{name}, &Empty{}, 2*time.Minute); err != nil {
		return err
	}
	if err := c.syncProviderCaches(); err != nil {
		return fmt.Errorf("%w: %v", ErrProviderCacheSync, err)
	}
	return nil
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
