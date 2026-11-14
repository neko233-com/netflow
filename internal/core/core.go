package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	mihomodns "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/neko233-com/netflow/internal/safepath"
	"go.yaml.in/yaml/v3"
)

const configFileName = "config.yaml"

// Status is a snapshot of the running kernel. The UI reads this value
// and does not touch the mihomo singleton itself.
type Status struct {
	Running      bool
	Error        string
	Version      string
	MixedPort    int
	HTTPPort     int
	SOCKSPort    int
	RedirPort    int
	TProxyPort   int
	AllowLAN     bool
	IPv6         bool
	UnifiedDelay bool
	TUN          bool
	LogLevel     string
	Mode         string
	ConfigDir    string
}

// ProxyNode is one proxy inside a provider.
type ProxyNode struct {
	Name                        string
	Type                        string
	UDP, TFO, XUDP, MPTCP, SMUX bool
}

// Core controls the process-wide mihomo singleton.
type Core struct {
	mu                sync.Mutex
	running           bool
	dir               string
	profileID         string
	transform         func([]byte, string) ([]byte, error)
	effective         []byte
	disableController bool
	pendingFakeIP     *mihomodns.FakeIPState
}

// SetTransformer installs an in-memory transformation; the original config
// on disk remains unchanged.
func (c *Core) SetTransformer(fn func([]byte, string) ([]byte, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.transform = fn
}

func (c *Core) SetProfileID(id string) { c.mu.Lock(); defer c.mu.Unlock(); c.profileID = id }
func (c *Core) ProfileID() string      { c.mu.Lock(); defer c.mu.Unlock(); return c.profileID }

// New returns a core that is not running.
func New() *Core { return &Core{} }

// DisableExternalController is used by privileged kernel workers, which are
// controlled only through their authenticated private IPC connection.
func (c *Core) DisableExternalController() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disableController = true
}

// ExportFakeIPState is valid after Stop: the DNS listener is closed but its
// allocation table remains available until the process is torn down.
func (c *Core) ExportFakeIPState() (*mihomodns.FakeIPState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mapper := resolver.DefaultHostMapper
	if mapper == nil {
		return nil, nil
	}
	enhancer, ok := mapper.(*mihomodns.ResolverEnhancer)
	if !ok {
		return nil, errors.New("无法读取 Fake-IP 映射状态")
	}
	state, err := enhancer.ExportFakeIPState()
	if err != nil {
		return nil, err
	}
	if state.IPv4 == nil && state.IPv6 == nil {
		return nil, nil
	}
	return &state, nil
}

// StageFakeIPState installs state into the next DNS configuration before it
// opens its DNS or TUN listeners.
func (c *Core) StageFakeIPState(state *mihomodns.FakeIPState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return errors.New("运行中的内核不能接收 Fake-IP 状态")
	}
	c.pendingFakeIP = state
	return nil
}

// Start loads config.yaml from homeDir (writing DefaultConfig when the
// file is absent) and applies it with hub.Parse. homeDir becomes
// mihomo's configuration directory for this process.
func (c *Core) Start(homeDir string) error {
	if c == nil {
		return errors.New("core is nil")
	}
	if homeDir == "" {
		return errors.New("config dir is empty")
	}
	homeDir = filepath.Clean(homeDir)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return errors.New("core already running")
	}
	C.SetHomeDir(homeDir)
	C.SetConfig(filepath.Join(homeDir, configFileName))

	if err := c.apply(); err != nil {
		releaseListeners()
		return err
	}
	c.running = true
	c.dir = homeDir
	return nil
}

// Reload reads config.yaml from the directory passed to Start and applies
// it again.
func (c *Core) Reload() error {
	if c == nil {
		return errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return errors.New("core is not running")
	}
	return c.apply()
}

// Stop closes listeners, the external controller and provider update
// loops. It is safe to call more than once.
func (c *Core) Stop() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	closeProviders()
	releaseListeners()
	c.running = false
	c.effective = nil
	return nil
}

// EffectiveConfig returns the last successfully applied composed YAML.
func (c *Core) EffectiveConfig() ([]byte, error) {
	if c == nil {
		return nil, errors.New("core is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || len(c.effective) == 0 {
		return nil, errors.New("内核未运行或没有可用配置")
	}
	return append([]byte(nil), c.effective...), nil
}

// Status reports the kernel. Version is set even when the core is stopped.
func (c *Core) Status() Status {
	st := Status{Version: Version()}
	if c == nil {
		return st
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st.Running = c.running
	st.ConfigDir = c.dir
	if !c.running {
		return st
	}
	general := executor.GetGeneral()
	st.MixedPort = general.MixedPort
	st.HTTPPort = general.Port
	st.SOCKSPort = general.SocksPort
	st.RedirPort = general.RedirPort
	st.TProxyPort = general.TProxyPort
	st.AllowLAN = general.AllowLan
	st.IPv6 = general.IPv6
	st.UnifiedDelay = general.UnifiedDelay
	st.TUN = general.Tun.Enable
	st.LogLevel = general.LogLevel.String()
	st.Mode = general.Mode.String()
	return st
}

// ProviderProxies returns the proxies loaded for a named provider.
// The slice is empty when the core is stopped or the provider is missing.
func (c *Core) ProviderProxies(name string) []ProxyNode {
	if c == nil || name == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	p, ok := tunnel.Providers()[name]
	if !ok || p == nil {
		return nil
	}
	proxies := p.Proxies()
	out := make([]ProxyNode, 0, len(proxies))
	for _, px := range proxies {
		out = append(out, ProxyNode{Name: px.Name(), Type: px.Type().String()})
	}
	return out
}

func (c *Core) apply() error {
	defer func() { c.pendingFakeIP = nil }()
	homeDir := C.Path.HomeDir()
	path := C.Path.Config()
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := writeDefaultConfig(path); err != nil {
		return err
	}
	data, err := safepath.ReadFile(homeDir, configFileName)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if c.transform != nil {
		data, err = c.transform(data, c.profileID)
		if err != nil {
			return fmt.Errorf("compose agent rules: %w", err)
		}
	}
	// Apply a copy without a controller, then only enable the configured
	// HTTP controller if it is authenticated and bound to loopback.
	cfg, err := executor.ParseWithBytes(data)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	route.SetEmbedMode(true)
	suppressed, err := suppressExternalController(data)
	if err != nil {
		return fmt.Errorf("disable external controller: %w", err)
	}
	if c.pendingFakeIP == nil {
		if err := hub.Parse(suppressed); err != nil {
			return fmt.Errorf("apply config: %w", err)
		}
	} else {
		safeConfig, err := executor.ParseWithBytes(suppressed)
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
		if safeConfig.DNS == nil {
			return errors.New("Fake-IP 状态与 DNS 配置不兼容")
		}
		if state := c.pendingFakeIP.IPv4; state != nil {
			if safeConfig.DNS.FakeIPPool == nil {
				return errors.New("Fake-IP IPv4 状态与 DNS 配置不兼容")
			}
			if err := safeConfig.DNS.FakeIPPool.ImportSnapshot(*state); err != nil {
				return fmt.Errorf("恢复 Fake-IP IPv4 状态: %w", err)
			}
		}
		if state := c.pendingFakeIP.IPv6; state != nil {
			if safeConfig.DNS.FakeIPPool6 == nil {
				return errors.New("Fake-IP IPv6 状态与 DNS 配置不兼容")
			}
			if err := safeConfig.DNS.FakeIPPool6.ImportSnapshot(*state); err != nil {
				return fmt.Errorf("恢复 Fake-IP IPv6 状态: %w", err)
			}
		}
		hub.ApplyConfigWithRestoredFakeIP(safeConfig)
	}
	actual := executor.GetGeneral()
	if err := verifyTUNState(cfg.General.Tun.Enable, actual.Tun.Enable); err != nil {
		return err
	}
	for _, port := range []struct {
		name      string
		want, got int
	}{
		{"mixed", cfg.General.MixedPort, actual.MixedPort}, {"HTTP", cfg.General.Port, actual.Port}, {"SOCKS", cfg.General.SocksPort, actual.SocksPort},
		{"redir", cfg.General.RedirPort, actual.RedirPort}, {"tproxy", cfg.General.TProxyPort, actual.TProxyPort},
	} {
		if port.want != port.got {
			return fmt.Errorf("%s proxy port %d could not be opened (actual %d)", port.name, port.want, port.got)
		}
	}
	if !c.disableController {
		startExternalController(cfg.Controller.ExternalController, cfg.Controller.Secret, cfg.General.LogLevel == log.DEBUG)
	}
	c.effective = append(c.effective[:0], data...)
	return nil
}

func verifyTUNState(wanted, actual bool) error {
	if wanted && !actual {
		return errors.New("虚拟网卡启动失败，请检查管理员权限、驱动及日志")
	}
	if !wanted && actual {
		return errors.New("虚拟网卡未能关闭")
	}
	return nil
}

// suppressExternalController disables controller endpoints in a copy of the
// configuration, including endpoints inherited through YAML merge keys.
func suppressExternalController(data []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config must be a YAML mapping")
	}
	root := doc.Content[0]
	// Explicit empty values override YAML merge keys as well as direct keys.
	for _, key := range []string{"external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-ui"} {
		value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}
		found := false
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				root.Content[i+1] = value
				found = true
				break
			}
		}
		if !found {
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
		}
	}
	return yaml.Marshal(&doc)
}

func writeDefaultConfig(path string) error {
	created, err := safepath.CreateExclusive(filepath.Dir(path), filepath.Base(path), []byte(DefaultConfig), false)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	return created.Close()
}

func releaseListeners() {
	listener.ReCreateHTTP(0, tunnel.Tunnel)
	listener.ReCreateSocks(0, tunnel.Tunnel)
	listener.ReCreateRedir(0, tunnel.Tunnel)
	listener.ReCreateTProxy(0, tunnel.Tunnel)
	listener.ReCreateMixed(0, tunnel.Tunnel)
	listener.Cleanup()
	mihomodns.ReCreateServer("", nil, nil)
	route.ReCreateServer(&route.Config{})
	executor.Shutdown()
}

func closeProviders() {
	for _, p := range tunnel.Providers() {
		closeIfPossible(p)
	}
	for _, p := range tunnel.RuleProviders() {
		closeIfPossible(p)
	}
}

func closeIfPossible(v any) {
	if c, ok := v.(io.Closer); ok && c != nil {
		_ = c.Close()
	}
}
