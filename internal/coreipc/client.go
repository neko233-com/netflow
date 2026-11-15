package coreipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
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
	reloadMu      sync.Mutex
	stopMu        sync.Mutex
	stopping      bool
	stopSignal    chan struct{}
	reloadSignal  chan struct{}
	reloadPending bool
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

// ErrKernelBusy means no reload was attempted because another serialized
// kernel operation is still using the private worker.
var ErrKernelBusy = errors.New("内核正忙，请等待集合更新或缓存同步结束后重试")

// ErrKernelStoppedBeforeFinalization means the worker confirmed that its
// kernel stopped, but the subsequent final cache/stop exchange failed.
var ErrKernelStoppedBeforeFinalization = errors.New("kernel stopped before final cache synchronization completed")

func NewClient(c io.ReadWriteCloser) (*Client, error) {
	if c == nil {
		return nil, errors.New("nil kernel transport")
	}
	return &Client{rpc: rpc.NewClient(c), cacheStop: make(chan struct{}), stopSignal: make(chan struct{}), reloadSignal: make(chan struct{}), cacheInterval: 30 * time.Second}, nil
}

func (c *Client) isStopping() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.stopping }

func (c *Client) stopSignalSnapshot() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopSignal
}

func (c *Client) signalStopping() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopping = true
	if c.stopSignal != nil {
		select {
		case <-c.stopSignal:
		default:
			close(c.stopSignal)
		}
	}
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

// Provider pause requests carry their own expiration. A slow provider must not
// close the transport and tear down an otherwise healthy TUN on timeout.
func (c *Client) providerPauseCall(method string, in any, timeout time.Duration) error {
	done := c.rpc.Go("Kernel."+method, in, &Empty{}, make(chan *rpc.Call, 1)).Done
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.Error
	case <-timer.C:
		return fmt.Errorf("kernel %s timed out", method)
	}
}

// CancelActiveApply is independent of applyMu so it can interrupt a reload
// that is itself waiting for a provider. A timeout does not close the TUN
// transport; the worker rejects a request that arrives after its deadline.
func (c *Client) CancelActiveApply(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var out BoolResult
	done := c.rpc.Go("Kernel.CancelApply", ApplyCancellation{Deadline: deadline.UnixNano()}, &out, make(chan *rpc.Call, 1)).Done
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case call := <-done:
		return out.Value, call.Error
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, errors.New("kernel apply cancellation timed out")
	}
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
	if c.isStopping() {
		return errors.New("kernel is stopping")
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
	if err := c.call("Start", Apply{Directory: dir, Config: data, Files: files}, &Empty{}, 45*time.Second); err != nil {
		return err
	}
	c.mu.Lock()
	c.dir = dir
	if !c.stopping {
		c.stopSignal = make(chan struct{})
	}
	c.mu.Unlock()
	c.caches = newCacheState(files, capabilities.IsolatedFiles)
	if capabilities.IsolatedFiles {
		c.startCacheLoop()
	}
	return nil
}
func (c *Client) Reload() error {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	if c.isStopping() {
		return errors.New("kernel is stopping")
	}
	c.mu.Lock()
	c.reloadPending = true
	if c.reloadSignal != nil {
		close(c.reloadSignal)
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.reloadPending = false; c.reloadSignal = make(chan struct{}); c.mu.Unlock() }()
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	deadline := time.Now().Add(3 * time.Second)
	if err := c.providerPauseCall("PauseProviderUpdates", ProviderPause{Token: token, Deadline: deadline.UnixNano()}, 4*time.Second); err != nil {
		return fmt.Errorf("pause provider updates: %w", err)
	}
	locked := false
	defer func() {
		if err := c.providerPauseCall("ResumeProviderUpdates", Name{token}, 4*time.Second); err != nil {
			log.Printf("resume provider updates: %v", err)
		}
		if locked {
			c.applyMu.Unlock()
		}
	}()
	wait := time.NewTimer(5 * time.Second)
	defer wait.Stop()
	for !c.applyMu.TryLock() {
		select {
		case <-wait.C:
			return ErrKernelBusy
		case <-c.stopSignalSnapshot():
			return errors.New("kernel is stopping")
		case <-time.After(10 * time.Millisecond):
		}
	}
	locked = true
	if c.isStopping() {
		return errors.New("kernel is stopping")
	}
	// Persist completed provider writes before staging user files back into the
	// worker. A failed snapshot aborts reload instead of overwriting fresh data.
	c.mu.Lock()
	c.reloadPending = false
	c.reloadSignal = make(chan struct{})
	c.mu.Unlock()
	if err := c.syncProviderCachesWithTimeout(3 * time.Second); err != nil {
		return fmt.Errorf("provider cache before reload: %w", err)
	}
	return c.reloadLocked()
}

// TryReload never waits behind a provider update or cache synchronization.
// ErrKernelBusy guarantees no reload request was sent to the worker.
func (c *Client) TryReload() error {
	if !c.applyMu.TryLock() {
		return ErrKernelBusy
	}
	defer c.applyMu.Unlock()
	c.mu.Lock()
	busy := c.reloadPending || c.cachePending
	c.mu.Unlock()
	if busy {
		return ErrKernelBusy
	}
	if c.isStopping() {
		return errors.New("kernel is stopping")
	}
	return c.reloadLocked()
}

func (c *Client) reloadLocked() error {
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
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	c.signalStopping()
	defer func() { c.mu.Lock(); c.stopping = false; c.mu.Unlock() }()
	interrupted := false
	if !c.applyMu.TryLock() {
		// The worker stops its kernel and cancels provider requests without
		// waiting for this client's serialized update or snapshot operation.
		if err := c.call("InterruptForStop", Empty{}, &Empty{}, 15*time.Second); err != nil {
			return errors.Join(fmt.Errorf("interrupt kernel before stop: %w", err), c.Close())
		}
		interrupted = true
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for !c.applyMu.TryLock() {
			select {
			case <-ticker.C:
			case <-deadline.C:
				return errors.Join(ErrKernelStoppedBeforeFinalization, errors.New("kernel operation did not stop after interruption"), c.Close())
			}
		}
	}
	defer c.applyMu.Unlock()
	var caches ProviderCaches
	if err := c.call("Stop", c.cacheQuery(), &caches, 45*time.Second); err != nil {
		if interrupted {
			return errors.Join(ErrKernelStoppedBeforeFinalization, err)
		}
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
	if c.isStopping() {
		return errors.New("kernel is stopping")
	}
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
func (c *Client) ProviderMembers(name string) ([]core.ProxyNode, error) {
	var out ProxyNodes
	err := c.short("ProviderMembers", Name{name}, &out)
	return out.Items, err
}
func (c *Client) ResolveIconHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out TextListResult
	if err := c.call("ResolveIconHost", Name{host}, &out, 6*time.Second); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(out.Values))
	for _, item := range out.Values {
		address, err := netip.ParseAddr(item)
		if err != nil {
			return nil, errors.New("invalid kernel DNS response")
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
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
	if c.isStopping() {
		return errors.New("kernel is stopping")
	}
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
	if err == nil && out.Canceled {
		return 0, context.Canceled
	}
	if err == nil && out.TimedOut {
		return 0, context.DeadlineExceeded
	}
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
