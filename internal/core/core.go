package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	mihomodns "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

const configFileName = "config.yaml"

// Status is a snapshot of the running kernel. The UI reads this value
// and does not touch the mihomo singleton itself.
type Status struct {
	Running   bool
	Version   string
	MixedPort int
	Mode      string
	ConfigDir string
}

// ProxyNode is one proxy inside a provider.
type ProxyNode struct {
	Name string
	Type string
}

// Core controls the process-wide mihomo singleton.
type Core struct {
	mu      sync.Mutex
	running bool
	dir     string
}

// New returns a core that is not running.
func New() *Core { return &Core{} }

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

	if err := apply(); err != nil {
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
	return apply()
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
	return nil
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

func apply() error {
	homeDir := C.Path.HomeDir()
	path := C.Path.Config()
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := writeDefaultConfig(path); err != nil {
		return err
	}
	if err := config.Init(homeDir); err != nil {
		return fmt.Errorf("init config dir: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	// Parse once for the controller address, then hub.Parse a copy that
	// does not start it. mihomo v1.19.33's hub.ApplyConfig launches the
	// external controller before it sets the log level, and the race
	// detector flags that. The controller is started after hub.Parse
	// returns. See startExternalController.
	cfg, err := executor.ParseWithBytes(data)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	route.SetEmbedMode(true)
	if err := hub.Parse(suppressExternalController(data)); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}
	actual := executor.GetGeneral()
	if cfg.General.MixedPort > 0 && actual.MixedPort != cfg.General.MixedPort {
		return fmt.Errorf("mixed proxy port %d could not be opened", cfg.General.MixedPort)
	}
	startExternalController(cfg.Controller.ExternalController, cfg.Controller.Secret, cfg.General.LogLevel == log.DEBUG)
	return nil
}

// suppressExternalController drops top-level external-controller lines so
// hub.Parse does not start the HTTP API. The file on disk is unchanged.
func suppressExternalController(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "external-controller") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

func writeDefaultConfig(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	defer f.Close()
	if _, err := io.WriteString(f, DefaultConfig); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
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
