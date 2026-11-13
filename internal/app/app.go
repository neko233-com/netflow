// Package app wires the kernel, settings and the native window.
package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/autostart"
	"github.com/neko233-com/netflow/internal/clashlog"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/service"
	"github.com/neko233-com/netflow/internal/sitetest"
	"github.com/neko233-com/netflow/internal/sysinfo"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/unlock"

	"github.com/egoist/mygo"
)

// Options selects the pieces a test can replace. Zero values get the
// user config directory, a file store, the macOS system proxy on darwin
// (an in-memory proxy elsewhere), and a TUN controller that only
// remembers the switch.
type Options struct {
	Dirs      appdir.Provider
	Store     appconfig.Store
	Proxy     sysproxy.Controller
	AutoStart autostart.Controller
	TUN       tun.Controller
	Service   service.Manager
	Core      *core.Core
}

// App is one running Clash Go process.
type App struct {
	dirs      appdir.Provider
	store     appconfig.Store
	proxy     sysproxy.Controller
	autostart autostart.Controller
	tun       tun.Controller
	svc       service.Manager
	core      *core.Core

	settings        appconfig.Settings
	model           *ui.Model
	dir             string
	profiles        *profile.Store
	sites           *sitetest.Store
	started         time.Time
	rewrites        *rewrite.Store
	kernelOptions   *kernelopts.Store
	agentBridge     *agent.Bridge
	agentProposals  map[string]agentProposal
	agentExpiryStop chan struct{}

	win  *mygo.Window
	tray *mygo.Tray

	connTrack        conn.Tracker
	logs             *clashlog.Buffer
	stopLogs         func()
	liveStop         chan struct{}
	probeSlots       chan struct{}
	probeStop        chan struct{}
	profileAutoStop  chan struct{}
	profileAutoRetry map[string]time.Time
	shortcuts        shortcutRegistrar
	hotkeys          map[string]hotkeyBinding
}

// New checks options and fills the M1 defaults. It does not start the
// kernel or the window.
func New(opt Options) *App {
	if opt.Dirs == nil {
		opt.Dirs = appdir.Default{}
	}
	if opt.Proxy == nil {
		opt.Proxy = sysproxy.Platform()
	}
	if opt.AutoStart == nil {
		opt.AutoStart = autostart.Platform()
	}
	if opt.TUN == nil {
		opt.TUN = tun.Platform()
	}
	if opt.Service == nil {
		opt.Service = service.Platform()
	}
	if opt.Core == nil {
		opt.Core = core.New()
	}
	return &App{
		dirs:      opt.Dirs,
		store:     opt.Store,
		proxy:     opt.Proxy,
		autostart: opt.AutoStart,
		tun:       opt.TUN,
		svc:       opt.Service,
		core:      opt.Core,
	}
}

// Prepare loads settings, starts the kernel in dir, and builds the home
// snapshot. The window is created separately so tests can stop here.
func (a *App) Prepare() error {
	dir, err := a.dirs.ConfigDir()
	if err != nil {
		return err
	}
	a.dir = dir
	if a.store == nil {
		a.store = appconfig.NewFileStore(dir)
	}
	settings, err := a.store.Load()
	if err != nil {
		return err
	}
	if owned, ok := a.proxy.(interface{ Owned() (bool, error) }); ok {
		active, err := owned.Owned()
		if err != nil {
			return err
		}
		if settings.SystemProxy != active {
			settings.SystemProxy = active
			if err := a.store.Save(settings); err != nil {
				return err
			}
		}
	}
	a.settings = settings
	if settings.TUN && !a.tunAllowed() {
		settings.TUN = false
		if err := a.store.Save(settings); err != nil {
			return fmt.Errorf("关闭不可用的 TUN 设置: %w", err)
		}
		a.settings = settings
	}
	a.profiles = profile.NewStore(dir)
	osName, osVersion := sysinfo.Current()
	a.model = ui.NewModel(ui.HomeState{ConfigDir: dir, Version: core.Version(), OS: osName, OSVersion: osVersion})
	a.applySettings()
	for _, page := range ui.Pages() {
		if page.Path == a.model.Prefs.StartPage {
			a.model.Router.Replace(page.Path)
			break
		}
	}
	if active, err := a.autostart.Current(); err == nil {
		a.model.Prefs.AutoLaunch = active
		a.model.Home.AutoLaunch = active
	}
	a.loadProfiles()
	a.loadSites()
	a.rewrites, err = rewrite.Open(dir)
	if err != nil {
		return fmt.Errorf("读取 Agent 规则: %w", err)
	}
	a.kernelOptions, err = kernelopts.Open(dir)
	if err != nil {
		return fmt.Errorf("读取内核选项: %w", err)
	}
	a.core.SetTransformer(func(base []byte, profileID string) ([]byte, error) {
		if !a.tunAllowed() {
			var err error
			base, err = tun.EnsureDisabled(base)
			if err != nil {
				return nil, err
			}
		}
		state := a.rewrites.Snapshot()
		now := time.Now()
		if rewrite.HasActive(state, profileID, now) {
			var err error
			base, _, err = rewrite.Compose(base, state, profileID, now)
			if err != nil {
				return nil, err
			}
		}
		return kernelopts.Compose(base, a.kernelOptions.Snapshot())
	})
	a.core.SetProfileID(a.model.CurrentProfile)
	if err := a.installCurrentProfile(); err != nil {
		a.model.Notice = err.Error()
	}
	if err := a.core.Start(dir); err != nil {
		if settings.SystemProxy {
			if restore, ok := a.proxy.(interface{ Restore() error }); ok {
				if restoreErr := restore.Restore(); restoreErr == nil {
					settings.SystemProxy = false
					a.settings.SystemProxy = false
					_ = a.store.Save(settings)
				} else {
					logMessage := "系统代理恢复失败: " + restoreErr.Error()
					a.model.Notice = logMessage
				}
			}
		}
		a.model.Home.Version = core.Version()
		a.model.Home.Running = false
		a.model.Home.ConfigDir = dir
		a.model.Home.Error = err.Error()
		a.model.Home.SystemProxy = settings.SystemProxy
		a.model.Home.TUN = settings.TUN
		a.bindHooks()
		return nil
	}
	a.started = time.Now()
	a.loadGroups()
	a.bindHooks()
	a.refreshHome()
	return nil
}

func (a *App) applySettings() {
	prefs := ui.DefaultPrefs()
	if a.settings.Prefs != "" {
		_ = json.Unmarshal([]byte(a.settings.Prefs), &prefs)
	}
	prefs.SystemProxy = a.settings.SystemProxy
	prefs.TUN = a.settings.TUN
	if a.settings.TrayEvent != "" {
		prefs.TrayEvent = a.settings.TrayEvent
	}
	if a.settings.ProxyMenu != "" {
		prefs.ProxyMenu = a.settings.ProxyMenu
	}
	prefs.InlineModes = a.settings.InlineModes
	prefs.Lightweight = a.settings.Lightweight
	a.model.Prefs = prefs
	a.model.Home.SystemProxy = prefs.SystemProxy
	a.model.Home.TUN = prefs.TUN
	a.model.Home.AutoLaunch = prefs.AutoLaunch
	a.model.Home.TUNAvailable = a.tunAllowed()
	a.model.ServiceInstalled = a.serviceReady()
}

func (a *App) loadProfiles() {
	if a.profiles == nil {
		return
	}
	file, err := a.profiles.Load()
	if err != nil {
		a.model.Notice = err.Error()
		return
	}
	a.model.Profiles = nil
	a.model.CurrentProfile = file.Current
	for _, it := range file.Items {
		item := ui.ProfileItem{
			UID: it.UID, Name: it.Name, Description: it.Description, URL: it.URL, Type: it.Type,
			Home: it.Home, Updated: it.Updated, Used: it.Used, Total: it.Total, Expire: it.Expire,
			Option: ui.ProfileOption{
				UpdateInterval: it.Option.UpdateInterval, UseSystemProxy: it.Option.UseSystemProxy,
				UseClashProxy: it.Option.UseClashProxy, AcceptInvalid: it.Option.AcceptInvalid,
				AllowAutoUpdate: it.Option.AllowAutoUpdate, Rules: it.Option.Rules, Proxies: it.Option.Proxies,
				Groups: it.Option.Groups, Merge: it.Option.Merge, Script: it.Option.Script,
				UserAgent: it.Option.UserAgent, TimeoutSeconds: it.Option.TimeoutSeconds,
			},
		}
		for _, sel := range it.Selected {
			item.Selected = append(item.Selected, ui.ProfileSelected{Name: sel.Name, Now: sel.Now})
		}
		a.model.Profiles = append(a.model.Profiles, item)
	}
	if cur := a.model.CurrentItem(); cur != nil {
		a.model.Home.Profile = &ui.HomeProfile{Name: cur.Name, URL: cur.URL, Home: cur.Home, Updated: cur.Updated, Used: cur.Used, Total: cur.Total, Expire: cur.Expire}
	}
}

// loadSites replaces the default list when tests.json exists.
// A missing file keeps DefaultSites. Delay is not stored.
func (a *App) loadSites() {
	if a == nil || a.model == nil || a.dir == "" {
		return
	}
	if a.sites == nil {
		a.sites = sitetest.NewStore(a.dir)
	}
	items, err := a.sites.Load()
	if err != nil {
		a.model.Notice = err.Error()
		return
	}
	if items == nil {
		return
	}
	a.model.Sites = nil
	for _, it := range items {
		a.model.Sites = append(a.model.Sites, ui.SiteTest{
			UID: it.UID, Name: it.Name, URL: it.URL, Icon: it.Icon, Delay: -1,
		})
	}
}

func (a *App) saveSites(list []ui.SiteTest) error {
	if a == nil || a.dir == "" {
		return nil
	}
	if a.sites == nil {
		a.sites = sitetest.NewStore(a.dir)
	}
	items := make([]sitetest.Item, 0, len(list))
	for _, s := range list {
		items = append(items, sitetest.Item{UID: s.UID, Name: s.Name, URL: s.URL, Icon: s.Icon})
	}
	return a.sites.Save(items)
}

func (a *App) probeSite(raw string) (int, error) {
	return sitetest.ProbeURL(raw, nil)
}

// SetSystemProxy asks the proxy controller to enable or disable the
// system proxy and stores the result. It does not read the kernel
// singleton from the UI; the endpoint comes from the last status.
func (a *App) SetSystemProxy(on bool) error {
	if on && a.model != nil && (a.core == nil || !a.core.Status().Running || a.core.Status().MixedPort == 0) {
		return errors.New("内核或混合代理端口未运行，不能开启系统代理")
	}
	endpoint := a.proxyEndpoint()
	next := sysproxy.Settings{Enabled: on, HTTP: endpoint, SOCKS: endpoint}
	if err := a.proxy.Set(next); err != nil {
		return err
	}
	prev := a.settings.SystemProxy
	a.settings.SystemProxy = on
	if err := a.store.Save(a.settings); err != nil {
		a.settings.SystemProxy = prev
		_ = a.proxy.Set(sysproxy.Settings{Enabled: prev, HTTP: endpoint, SOCKS: endpoint})
		return err
	}
	a.refreshHome()
	return nil
}

// SetTUN asks the TUN controller to enable or disable TUN, rewrites the
// mihomo profile, and stores the switch. Missing permission does not write
// tun.enable or the saved switch. CI never reloads a running kernel into TUN.
func (a *App) SetTUN(on bool) error {
	if on && !a.tunAllowed() {
		if a.model != nil {
			a.model.Home.TUN = false
			a.model.Home.TUNAvailable = false
			a.model.Notice = tun.ErrNeedService.Error()
		}
		return tun.ErrNeedService
	}
	if err := a.applyTUNFile(on); err != nil {
		return err
	}
	if a.serviceReady() {
		if err := a.svc.StartCore(a.dir); err != nil {
			_ = a.applyTUNFile(!on)
			return err
		}
	} else if a.tun != nil {
		if err := a.tun.Set(on); err != nil {
			_ = a.applyTUNFile(!on)
			return err
		}
	}
	prev := a.settings.TUN
	a.settings.TUN = on
	if a.store != nil {
		if err := a.store.Save(a.settings); err != nil {
			a.settings.TUN = prev
			if a.tun != nil {
				_ = a.tun.Set(prev)
			}
			_ = a.applyTUNFile(prev)
			return err
		}
	}
	a.refreshHome()
	return nil
}

func (a *App) applyTUNFile(on bool) error {
	if a == nil || a.dir == "" {
		return nil
	}
	path := filepath.Join(a.dir, "config.yaml")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if on && tunCIBlocked() && a.core != nil && a.core.Status().Running {
		return tun.ErrNeedService
	}
	if err := tun.ApplyFile(path, on); err != nil {
		return err
	}
	// The helper process reloads the core. Reloading here as well would
	// start mihomo a second time in this process.
	if a.serviceReady() {
		return nil
	}
	if a.core != nil && a.core.Status().Running {
		return a.core.Reload()
	}
	return nil
}

func (a *App) tunAllowed() bool {
	if a.serviceReady() {
		return true
	}
	return a.tun != nil && a.tun.Available()
}

func (a *App) serviceReady() bool {
	if a == nil || a.svc == nil {
		return false
	}
	st, err := a.svc.Status()
	return err == nil && st.Installed
}

func (a *App) checkUnlock(name string) (string, string, int, error) {
	client := unlock.ProxyClient(a.proxyEndpoint(), 0)
	res, err := unlock.Check(name, client)
	if err != nil {
		return "", "", 0, err
	}
	return res.Status, res.Region, res.Delay, nil
}

// InstallService asks the helper manager to install the launchd daemon.
// CI refuses. A successful install makes the TUN switch usable.
func (a *App) InstallService() error {
	if a == nil || a.svc == nil {
		return service.ErrUnsupported
	}
	if err := a.svc.Install(); err != nil {
		return err
	}
	a.refreshHome()
	return nil
}

// UninstallService removes the helper and turns TUN off in the saved config.
func (a *App) UninstallService() error {
	if a == nil || a.svc == nil {
		return service.ErrUnsupported
	}
	if err := a.svc.Uninstall(); err != nil {
		return err
	}
	if a.settings.TUN {
		a.settings.TUN = false
		_ = a.applyTUNFile(false)
		if a.tun != nil {
			_ = a.tun.Set(false)
		}
		if a.store != nil {
			_ = a.store.Save(a.settings)
		}
	}
	a.refreshHome()
	return nil
}

func tunCIBlocked() bool {
	return os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
}

// Home is the snapshot the window shows.
func (a *App) Home() ui.HomeState {
	if a == nil || a.model == nil {
		return ui.HomeState{}
	}
	return a.model.Home
}

// Model is the window model. Nil before Prepare.
func (a *App) Model() *ui.Model { return a.model }

func (a *App) refreshHome() {
	if a.model == nil {
		return
	}
	st := a.core.Status()
	h := a.model.Home
	if st.Running {
		h.Rules = len(a.core.Rules())
	}
	if st.Running {
		a.model.Prefs.AllowLan = st.AllowLAN
		a.model.Prefs.IPv6 = st.IPv6
		a.model.Prefs.UnifiedDelay = st.UnifiedDelay
		a.model.Prefs.LogLevel = st.LogLevel
		a.model.Prefs.MixedPort = st.MixedPort
		a.model.Prefs.SocksOn = st.SOCKSPort > 0
		if st.SOCKSPort > 0 {
			a.model.Prefs.SocksPort = st.SOCKSPort
		}
		a.model.Prefs.HTTPOn = st.HTTPPort > 0
		if st.HTTPPort > 0 {
			a.model.Prefs.HTTPPort = st.HTTPPort
		}
		a.model.Prefs.RedirOn = st.RedirPort > 0
		if st.RedirPort > 0 {
			a.model.Prefs.RedirPort = st.RedirPort
		}
		a.model.Prefs.TProxyOn = st.TProxyPort > 0
		if st.TProxyPort > 0 {
			a.model.Prefs.TProxyPort = st.TProxyPort
		}
	}
	h.Version = st.Version
	h.Running = st.Running
	if st.MixedPort > 0 {
		h.MixedPort = st.MixedPort
	}
	if st.Mode != "" {
		h.Mode = st.Mode
	}
	h.ConfigDir = a.dir
	h.SystemProxy = a.settings.SystemProxy
	h.TUN = a.settings.TUN
	h.TUNAvailable = a.tunAllowed()
	if a.serviceReady() {
		a.model.ServiceInstalled = true
		if h.RunMode == "" || h.RunMode == ui.RunSidecar {
			h.RunMode = ui.RunService
		}
	} else {
		a.model.ServiceInstalled = false
		if h.RunMode == ui.RunService {
			h.RunMode = ui.RunSidecar
		}
	}
	if st.Running && !a.started.IsZero() {
		h.Uptime = time.Since(a.started)
	}
	a.model.Home = h
	a.model.Prefs.SystemProxy = a.settings.SystemProxy
	a.model.Prefs.TUN = a.settings.TUN
	if a.win != nil {
		a.win.Invalidate()
	}
	if a.tray != nil {
		a.tray.SetMenu(BuildTrayMenu(a.traySnapshot(), a.trayActions()))
	}
}

func (a *App) installCurrentProfile() error {
	if a.profiles == nil || a.model == nil {
		return nil
	}
	cur := a.model.CurrentItem()
	if cur == nil {
		return nil
	}
	file, err := a.profiles.Load()
	if err != nil {
		return err
	}
	var rel string
	for _, it := range file.Items {
		if it.UID == cur.UID {
			rel = it.File
		}
	}
	if rel == "" {
		return nil
	}
	body, err := os.ReadFile(filepath.Join(a.dir, rel))
	if err != nil {
		return err
	}
	body = profile.EnsureMixedPort(body, 7897)
	return os.WriteFile(filepath.Join(a.dir, "config.yaml"), body, 0o600)
}

func (a *App) loadGroups() {
	if a.model == nil || a.dir == "" {
		return
	}
	body, err := os.ReadFile(filepath.Join(a.dir, "config.yaml"))
	if err != nil {
		return
	}
	parsed, err := profile.ParseClashYAML(body)
	if err != nil {
		a.model.Notice = err.Error()
		return
	}
	if parsed.Rules > 0 {
		a.model.Home.Rules = parsed.Rules
	}
	if a.core != nil && a.core.Status().Running && a.core.Status().Mode == "global" {
		found := false
		for _, g := range parsed.Groups {
			if g.Name == "GLOBAL" {
				found = true
				break
			}
		}
		if !found {
			parsed.Groups = append([]profile.Group{{Name: "GLOBAL", Type: "select"}}, parsed.Groups...)
		}
	}
	previous := make(map[string]ui.ProxyGroup, len(a.model.Groups))
	for _, g := range a.model.Groups {
		previous[g.Name] = g
	}
	groups := make([]ui.ProxyGroup, 0, len(parsed.Groups))
	for _, g := range parsed.Groups {
		gg := ui.ProxyGroup{Name: g.Name, Type: g.Type, Now: g.Now, Open: true, ShowDetail: true}
		if old, ok := previous[g.Name]; ok {
			gg.Open = old.Open
			gg.Sort = old.Sort
			gg.ShowDetail = old.ShowDetail
			gg.FilterOpen = old.FilterOpen
			gg.FilterText = old.FilterText
			gg.FilterApplied = old.FilterApplied
			gg.FilterChanged = old.FilterChanged
			gg.URLOpen = old.URLOpen
			gg.TestURL = old.TestURL
		}
		var actual core.ProxyGroup
		var groupErr error
		if a.core != nil && a.core.Status().Running {
			actual, groupErr = a.core.Group(g.Name)
		} else {
			groupErr = errors.New("core stopped")
		}
		if groupErr == nil {
			gg.Type = actual.Type
			gg.Now = actual.Now
			gg.Icon = actual.Icon
			gg.Hidden = actual.Hidden
			for _, n := range actual.Nodes {
				gg.Nodes = append(gg.Nodes, ui.ProxyNode{Name: n.Name, Type: n.Type, Delay: -1, UDP: n.UDP, TFO: n.TFO, XUDP: n.XUDP, MPTCP: n.MPTCP, SMUX: n.SMUX, Preset: n.Name == "DIRECT" || n.Name == "REJECT"})
			}
		} else {
			for _, n := range g.Proxies {
				gg.Nodes = append(gg.Nodes, ui.ProxyNode{Name: n.Name, Type: n.Type, Delay: -1})
			}
		}
		if old, ok := previous[g.Name]; ok {
			delays := make(map[string]int, len(old.Nodes))
			for _, n := range old.Nodes {
				if n.Delay != ui.DelayTesting {
					delays[n.Name] = n.Delay
				}
			}
			for i := range gg.Nodes {
				if value, ok := delays[gg.Nodes[i].Name]; ok {
					gg.Nodes[i].Delay = value
				}
			}
		}
		groups = append(groups, gg)
	}
	a.model.Groups = groups
	a.model.Providers = nil
	if a.core != nil && a.core.Status().Running {
		for _, p := range a.core.ProxyProviders() {
			a.model.Providers = append(a.model.Providers, ui.ProxyProvider{Name: p.Name, Type: p.Vehicle, Count: p.Count})
		}
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		if !g.Hidden {
			names = append(names, g.Name)
		}
	}
	a.model.Home.Node = ui.CurrentNode{Groups: names}
	a.applySavedSelection()
}

// applySavedSelection is Verge's activateSelected. The current profile's
// selected list is one {name, now} per group. Each entry is written onto
// the model and, when the kernel is running, into that selector. A saved
// node that the group does not have is skipped and the group keeps its
// default (the YAML now, otherwise the first proxy, otherwise the kernel's
// current Now).
func (a *App) applySavedSelection() {
	if a.model == nil {
		return
	}
	saved := map[string]string{}
	if cur := a.model.CurrentItem(); cur != nil {
		for _, sel := range cur.Selected {
			if sel.Name == "" || sel.Now == "" {
				continue
			}
			if _, ok := saved[sel.Name]; !ok {
				saved[sel.Name] = sel.Now
			}
		}
	}
	running := a.core != nil && a.core.Status().Running
	for i := range a.model.Groups {
		g := &a.model.Groups[i]
		want, ok := saved[g.Name]
		if ok && groupHasNode(g, want) && ui.SelectableGroup(g.Type) {
			if running {
				if err := a.core.Select(g.Name, want); err != nil {
					g.Now = a.fallbackNow(g)
					continue
				}
				if now, err := a.core.Selected(g.Name); err == nil && groupHasNode(g, now) {
					g.Now = now
					continue
				}
			}
			g.Now = want
			continue
		}
		if g.Now == "" || !groupHasNode(g, g.Now) {
			g.Now = firstNode(g)
		}
		if running && ui.SelectableGroup(g.Type) {
			now, err := a.core.Selected(g.Name)
			if err == nil && groupHasNode(g, now) {
				g.Now = now
			} else if g.Now != "" {
				// The kernel still has another profile's node. Put it back
				// on this profile's default so the UI and Now() agree.
				if selErr := a.core.Select(g.Name, g.Now); selErr == nil {
					if now, err = a.core.Selected(g.Name); err == nil && groupHasNode(g, now) {
						g.Now = now
					}
				}
			}
		}
	}
	a.syncHomeNode()
}

func (a *App) fallbackNow(g *ui.ProxyGroup) string {
	if g == nil {
		return ""
	}
	if a.core != nil && a.core.Status().Running && ui.SelectableGroup(g.Type) {
		if now, err := a.core.Selected(g.Name); err == nil && groupHasNode(g, now) {
			return now
		}
	}
	if groupHasNode(g, g.Now) {
		return g.Now
	}
	return firstNode(g)
}

func (a *App) syncHomeNode() {
	if a.model == nil {
		return
	}
	h := a.model.Home.Node
	h.Name, h.Type, h.Group = "", "", ""
	h.Delay = 0
	for _, g := range a.model.Groups {
		if g.Hidden || !selectorGroup(g.Type) || g.Now == "" {
			continue
		}
		h.Name = g.Now
		h.Group = g.Name
		for _, n := range g.Nodes {
			if n.Name == g.Now {
				h.Type = n.Type
				h.Delay = n.Delay
				break
			}
		}
		break
	}
	if h.Group == "" && len(a.model.Groups) > 0 {
		for _, g := range a.model.Groups {
			if !g.Hidden && ui.SelectableGroup(g.Type) && g.Now != "" {
				h.Group = g.Name
				h.Name = g.Now
				for _, n := range g.Nodes {
					if n.Name == g.Now {
						h.Type = n.Type
						h.Delay = n.Delay
						break
					}
				}
				break
			}
		}
		if h.Group == "" {
			for _, g := range a.model.Groups {
				if !g.Hidden {
					h.Group = g.Name
					break
				}
			}
		}
	}
	a.model.Home.Node = h
}

func groupHasNode(g *ui.ProxyGroup, name string) bool {
	if g == nil || name == "" {
		return false
	}
	for _, n := range g.Nodes {
		if n.Name == name {
			return true
		}
	}
	return false
}

func firstNode(g *ui.ProxyGroup) string {
	if g == nil || len(g.Nodes) == 0 {
		return ""
	}
	return g.Nodes[0].Name
}

func selectorGroup(kind string) bool {
	switch strings.ToLower(kind) {
	case "selector", "select":
		return true
	default:
		return false
	}
}

// UseProfile makes uid the current subscription, reloads its config into
// the kernel, and restores that profile's selected nodes. This is the
// profile-switch half of activateSelected. Startup does the same work
// from Prepare via loadProfiles and loadGroups.
func (a *App) UseProfile(uid string) error {
	if a == nil || a.profiles == nil {
		return errors.New("订阅存储不可用")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return err
	}
	var rel string
	for _, item := range catalog.Items {
		if item.UID == uid {
			rel = item.File
			break
		}
	}
	if rel == "" {
		return errors.New("订阅不存在")
	}
	body, err := os.ReadFile(filepath.Join(a.dir, rel))
	if err != nil {
		return err
	}
	if err := validateProfile(body); err != nil {
		return err
	}
	if err := a.validateEffectiveProfile(body, uid); err != nil {
		return err
	}
	path := filepath.Join(a.dir, "config.yaml")
	old, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if err := os.WriteFile(path, profile.EnsureMixedPort(body, 7897), 0600); err != nil {
		return err
	}
	previousProfile := ""
	if a.core != nil {
		previousProfile = a.core.ProfileID()
		a.core.SetProfileID(uid)
	}
	rollback := func(cause error) error {
		if a.core != nil {
			a.core.SetProfileID(previousProfile)
		}
		var restoreErr error
		if readErr == nil {
			restoreErr = os.WriteFile(path, old, 0600)
		} else {
			restoreErr = os.Remove(path)
			if errors.Is(restoreErr, os.ErrNotExist) {
				restoreErr = nil
			}
		}
		if restoreErr == nil && a.core != nil && a.core.Status().Running && readErr == nil {
			restoreErr = a.core.Reload()
		}
		if restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("恢复之前的配置失败: %w", restoreErr))
		}
		return cause
	}
	if a.core != nil && a.core.Status().Running {
		if err := a.core.Reload(); err != nil {
			return rollback(err)
		}
	}
	if err := a.profiles.SetCurrent(uid); err != nil {
		return rollback(err)
	}
	a.loadProfiles()
	a.loadGroups()
	a.refreshHome()
	return nil
}

func (a *App) bindHooks() {
	if a.model == nil {
		return
	}
	a.model.Hooks = ui.Hooks{
		SetSystemProxy:      a.SetSystemProxy,
		SetAutoLaunch:       a.SetAutoLaunch,
		SetLightweight:      a.setLightweight,
		ChainAvailable:      func() bool { return false },
		SetTUN:              a.SetTUN,
		SetMode:             a.SetMode,
		SelectProxy:         a.SelectProxy,
		UseProfile:          a.UseProfile,
		CloseConnection:     a.closeConnection,
		CloseAllConnections: a.closeAllConnections,
		ClearClosed:         func() { a.connTrack.ClearClosed() },
		RefreshRules:        a.refreshRules,
		UpdateRuleProvider:  a.updateRuleProvider,
		SetLogPaused: func(on bool) {
			if a.logs != nil {
				a.logs.SetPaused(on)
			}
		},
		ClearLogs: func() {
			if a.logs != nil {
				a.logs.Clear()
			}
		},
		ImportURL:           a.ImportURL,
		ImportLocal:         a.ImportLocal,
		DeleteProfile:       a.DeleteProfile,
		UpdateProfile:       a.UpdateProfile,
		LoadRewrite:         a.loadRewrite,
		PreviewRewrite:      a.agentPreview,
		ApplyRewrite:        a.agentApply,
		SaveProfileMetadata: a.saveProfileMetadata,
		SetKernelOption:     a.SetKernelOption,
		SetKernelPorts:      a.SetKernelPorts,
		SavePrefs:           a.savePrefs,
		ProbeSite:           a.probeSite,
		SaveSites:           a.saveSites,
		InstallService:      a.InstallService,
		UninstallService:    a.UninstallService,
		CheckUnlock:         a.checkUnlock,
		OpenDir:             a.openDir,
		RestartCore:         a.restartCore,
		Copy:                writeClipboard,
		Quit:                func() { mygo.App.Quit() },
	}
}

func (a *App) saveProfileMetadata(form ui.ProfileForm) error {
	if a.profiles == nil {
		return errors.New("订阅存储不可用")
	}
	var auto *bool
	if form.Type == "remote" {
		auto = &form.Auto
	}
	if err := a.profiles.UpdateMetadata(form.UID, form.Name, form.Desc, auto, form.Interval); err != nil {
		return err
	}
	a.loadProfiles()
	a.refreshHome()
	return nil
}

func (a *App) SetAutoLaunch(on bool) error {
	if a == nil || a.autostart == nil {
		return autostart.ErrUnsupported
	}
	if err := a.autostart.Set(on); err != nil {
		return err
	}
	return nil
}

// SelectProxy writes the choice into mihomo's selector when the kernel is
// running, then remembers it on the current subscription. A profile write
// failure does not undo a selector that already changed. A selector error
// is returned so the UI can revert.
func (a *App) SelectProxy(group, node string) error {
	if a == nil {
		return nil
	}
	actual := node
	if a.core != nil && a.core.Status().Running {
		if err := a.core.Select(group, node); err != nil {
			return err
		}
		if now, err := a.core.Selected(group); err == nil && now != "" {
			actual = now
		}
	}
	a.applyProxySelection(group, actual)
	if err := a.persistSelection(group, node); err != nil && a.model != nil {
		a.model.Notice = err.Error()
	}
	if actual != node && a.model != nil {
		a.model.Notice = "已设置节点 " + node + "，当前实际使用 " + actual
	}
	return nil
}

func (a *App) applyProxySelection(group, node string) {
	if a == nil || a.model == nil {
		return
	}
	for i := range a.model.Groups {
		g := &a.model.Groups[i]
		if g.Name != group {
			continue
		}
		g.Now = node
		if a.model.Home.Node.Group == group || a.model.Home.Node.Group == "" {
			a.model.Home.Node.Name = node
			a.model.Home.Node.Group = group
			for _, n := range g.Nodes {
				if n.Name == node {
					a.model.Home.Node.Type = n.Type
					a.model.Home.Node.Delay = n.Delay
				}
			}
		}
	}
	if a.win != nil {
		a.win.Invalidate()
	}
	if a.tray != nil {
		a.tray.SetMenu(BuildTrayMenu(a.traySnapshot(), a.trayActions()))
	}
}

func (a *App) persistSelection(group, node string) error {
	if a == nil || a.profiles == nil || a.model == nil || a.model.CurrentProfile == "" {
		return nil
	}
	return a.profiles.RecordSelected(a.model.CurrentProfile, group, node)
}

// SetMode writes the profile mode and reloads the kernel when it is running.
func (a *App) SetMode(mode string) error {
	if mode != "rule" && mode != "global" && mode != "direct" {
		return errors.New("无效的代理模式")
	}
	if a.kernelOptions != nil {
		next := a.kernelOptions.Snapshot()
		next.Mode = &mode
		if err := a.applyKernelOptions(next); err != nil {
			return err
		}
		a.loadGroups()
		a.refreshHome()
		return nil
	}
	if a.dir == "" {
		return nil
	}
	path := filepath.Join(a.dir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, profile.SetMode(data, mode), 0o600); err != nil {
		return err
	}
	if a.core != nil && a.core.Status().Running {
		if err := a.core.Reload(); err != nil {
			restoreErr := os.WriteFile(path, data, 0600)
			if restoreErr == nil {
				restoreErr = a.core.Reload()
			}
			if restoreErr != nil {
				return errors.Join(err, fmt.Errorf("恢复原代理模式失败: %w", restoreErr))
			}
			return err
		}
	}
	if a.model != nil {
		a.model.Home.Mode = mode
	}
	return nil
}

// ImportURL stores a remote subscription and, when it is the current one,
// installs it as the kernel profile.
func (a *App) ImportURL(raw string) error {
	body, err := fetchProfile(raw)
	if err != nil {
		return err
	}
	return a.importURLData(raw, body)
}

func (a *App) importURLData(raw string, body []byte) error {
	if a.profiles == nil {
		a.profiles = profile.NewStore(a.dir)
	}
	if err := validateProfile(body); err != nil {
		return err
	}
	before, err := a.profiles.Load()
	if err != nil {
		return err
	}
	item, err := a.profiles.ImportRemote(raw, func(string) ([]byte, error) { return body, nil })
	if err != nil {
		return err
	}
	return a.finishProfileImport(before.Current, item.UID)
}

func (a *App) ImportLocal(path string) error {
	if a.profiles == nil {
		a.profiles = profile.NewStore(a.dir)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return err
	}
	if len(body) > 8<<20 {
		return errors.New("配置文件超过 8 MiB")
	}
	if err := validateProfile(body); err != nil {
		return err
	}
	before, err := a.profiles.Load()
	if err != nil {
		return err
	}
	item, err := a.profiles.ImportLocal(path, body)
	if err != nil {
		return err
	}
	return a.finishProfileImport(before.Current, item.UID)
}

func (a *App) finishProfileImport(previous, uid string) error {
	if previous == "" {
		if err := a.UseProfile(uid); err != nil {
			if restoreErr := a.profiles.DiscardFirstImport(uid); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("回滚导入失败: %w", restoreErr))
			}
			a.loadProfiles()
			return err
		}
	} else {
		a.loadProfiles()
	}
	return nil
}

func (a *App) DeleteProfile(uid string) error {
	if a.profiles == nil {
		return errors.New("订阅存储不可用")
	}
	var old rewrite.State
	var revision uint64
	changed := false
	if a.rewrites != nil {
		catalog, err := a.profiles.Load()
		if err != nil {
			return err
		}
		if catalog.Current == uid {
			return errors.New("请先切换到其他订阅，再删除当前订阅")
		}
		old = a.rewrites.Snapshot()
		next := a.rewrites.Snapshot()
		if _, ok := next.Profiles[uid]; ok {
			delete(next.Profiles, uid)
			changed = true
		}
		kept := next.Connections[:0]
		for _, item := range next.Connections {
			if item.ProfileID == uid {
				changed = true
			} else {
				kept = append(kept, item)
			}
		}
		next.Connections = kept
		if changed {
			saved, err := a.rewrites.Replace(next, old.Revision)
			if err != nil {
				return err
			}
			revision = saved.Revision
		}
	}
	err := a.profiles.Delete(uid)
	if err != nil && changed {
		catalog, loadErr := a.profiles.Load()
		stillExists := loadErr != nil
		for _, item := range catalog.Items {
			if item.UID == uid {
				stillExists = true
				break
			}
		}
		if stillExists {
			if _, restoreErr := a.rewrites.Replace(old, revision); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore profile rules: %w", restoreErr))
			}
		}
	}
	a.loadProfiles()
	return err
}

func (a *App) savePrefs(p ui.Prefs) error {
	next := a.settings
	next.SystemProxy = p.SystemProxy
	next.TUN = p.TUN
	next.TrayEvent = p.TrayEvent
	next.InlineModes = p.InlineModes
	next.ProxyMenu = p.ProxyMenu
	next.Lightweight = p.Lightweight
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	next.Prefs = string(b)
	if a.store != nil {
		if err := a.store.Save(next); err != nil {
			return err
		}
	}
	a.settings = next
	return nil
}

func (a *App) openDir(kind string) {
	path := a.dir
	switch kind {
	case "logs", "app-log", "core-log":
		path = filepath.Join(a.dir, "logs")
		_ = os.MkdirAll(path, 0o700)
	}
	if path == "" {
		return
	}
	_ = openPath(path)
}

func (a *App) restartCore() error {
	if a.core == nil || a.dir == "" {
		return nil
	}
	_ = a.core.Stop()
	if err := a.core.Start(a.dir); err != nil {
		return err
	}
	a.started = time.Now()
	a.loadGroups()
	a.refreshHome()
	return nil
}

func fetchProfile(raw string) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 8<<20 {
		return nil, errors.New("订阅超过 8 MiB")
	}
	return body, nil
}

func (a *App) proxyEndpoint() string {
	port := 7897
	if a.core != nil {
		if st := a.core.Status(); st.MixedPort > 0 {
			port = st.MixedPort
		}
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}
