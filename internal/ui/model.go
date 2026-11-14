package ui

import (
	"strings"
	"time"

	mygoui "github.com/egoist/mygo/ui"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/ipinfo"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/rules"
	"github.com/neko233-com/netflow/internal/update"
)

// Hooks are the app services a page calls. Nil hooks update the model only,
// which is what the headless tests do.
type Hooks struct {
	SetSystemProxy             func(on bool) error
	SetAutoLaunch              func(on bool) error
	SetLightweight             func(on bool) error
	ChainAvailable             func() bool
	SystemDark                 func() bool
	ApplyHotkeys               func(Prefs) error
	SetTUN                     func(on bool) error
	SetTUNAsync                func(on bool, done func(error))
	SetMode                    func(mode string) error
	SelectProxy                func(group, node string) error
	UseProfile                 func(uid string) error
	CloseConnection            func(id string) error
	CloseAllConnections        func() error
	ClearClosed                func()
	RefreshRules               func() ([]rules.Item, []rules.Provider)
	UpdateRuleProvider         func(name string) error
	UpdateRuleProviderAsync    func(name string, done func(error))
	UpdateProxyProviderAsync   func(name string, done func(error))
	UpdateGeoAsync             func(done func(int, error))
	SetLogPaused               func(paused bool)
	ClearLogs                  func()
	ImportURL                  func(url string) error
	ImportURLAsync             func(url string, done func(error))
	ImportLocal                func(path string) error
	DeleteProfile              func(uid string) error
	UpdateProfile              func(uid string) error
	UpdateProfileAsync         func(uid string, done func(error))
	UpdateProfileViaProxyAsync func(uid string, done func(error))
	BrowseProfiles             func() ([]string, error)
	BrowseBackup               func() (string, error)
	BrowseBackupDirectory      func() (string, error)
	SetBackupSchedule          func(bool, string, int) (agent.BackupSchedule, error)
	CreateBackupAsync          func(string, func(error)) error
	BrowseRestore              func() (string, string, error)
	RestoreBackupAsync         func(string, string, func(error)) error
	BrowseWebDAVArchive        func() (string, error)
	UploadWebDAVAsync          func(agent.WebDAVUploadArgs, func(string, error)) error
	SaveProfileMetadata        func(form ProfileForm) error
	SetProfileDNS              func(id string, enabled bool, text string) error
	LoadEffectiveConfig        func() (string, error)
	Diagnostics                func() (string, error)
	OpenProfileFile            func(id string) error
	CreateProfileAsync         func(form ProfileForm, done func(error))
	LoadRewrite                func(scope, profileID string) (rewrite.Layer, error)
	PreviewRewrite             func(change agent.Change) (agent.Preview, error)
	ApplyRewrite               func(id string) (agent.ApplyResult, error)
	SetKernelOption            func(name string, value any) error
	SetKernelPorts             func(PortSet) error
	SavePrefs                  func(Prefs) error
	ClearWebDAVSecret          func() error
	CopyWebDAVField            func(string) error
	OpenDir                    func(kind string)
	RestartCore                func() error
	BrowseScript               func() (string, error)
	Copy                       func(text string) error
	Quit                       func()
	TestSite                   func(url string) error
	ProbeSite                  func(url string) (int, error)
	ProbeSiteAsync             func(url string, done func(int, error))
	SaveSites                  func([]SiteTest) error
	InstallService             func() error
	UninstallService           func() error
	CheckUnlock                func(name string) (status, region string, ms int, err error)
	CheckUnlockAsync           func(name string, done func(string, string, int, error))
	TestProxyAsync             func(group, name, url string, done func(int, error))
	CheckUpdateAsync           func(done func(update.Result, error))
	QueryIPAsync               func(done func(ipinfo.Result, error))
}

// Model is the main window: a sidebar and the page it shows.
type Model struct {
	Router   *mygoui.Router
	Home     HomeState
	Cards    HomeCards
	Draft    HomeCards
	HomeEdit bool

	NetTab      int
	ChartSmooth bool
	Sites       []SiteTest
	IP          IPView
	IPShown     bool
	IPAuto      bool
	IPBusy      bool
	IPLeft      int

	Groups              []ProxyGroup
	Providers           []ProxyProvider
	ProviderBusy        bool
	Chain               ChainState
	ProxiesLoading      bool
	Profiles            []ProfileItem
	CurrentProfile      string
	ProfileURL          string
	ProfileBusy         bool
	Batch               bool
	BatchDeleteAsk      bool
	RuleEditor          RuleEditor
	UpdateDialog        bool
	UpdateResult        update.Result
	portsDraft          Prefs
	portsDraftActive    bool
	hotkeyDraft         Prefs
	hotkeyDraftActive   bool
	ShowNextUpdate      map[string]bool
	Form                ProfileForm
	DeleteUID           string
	Prefs               Prefs
	WebDAVSecretStored  bool
	BackupSchedule      agent.BackupSchedule
	BackupHours         string
	WebDAVURLDraft      string
	WebDAVUserDraft     string
	WebDAVPasswordDraft string
	BackupBusy          bool
	RestorePath         string
	Notice              string
	Busy                string
	DNSAsk              bool
	ProfileHasDNS       bool
	DNSDraft            string
	DNSProfileID        string
	RuntimeConfig       string
	QRImage             mygoui.ImageSource
	QRURL               string
	QROpen              bool
	ForceTray           bool
	Dialogs             dialogSet
	Hooks               Hooks
	Conns               ConnView
	Rules               RuleView
	Logs                LogView
	TestForm            TestForm
	TunStack            string
	ServiceInstalled    bool
	ServiceRunning      bool
	Unlocks             []UnlockItem
}

type dialogSet struct {
	Provider bool
	Theme    bool
	Layout   bool
	Misc     bool
	Hotkey   bool
	Backup   bool
	Ports    bool
	Sysproxy bool
	TUN      bool
	Service  bool
	WebDAV   bool
	DNS      bool
	Runtime  bool
	Lite     bool
}

// NewModel returns a window opened on the home page.
func NewModel(home HomeState) *Model {
	if home.Mode == "" {
		home.Mode = "rule"
	}
	if home.VergeVersion == "" {
		home.VergeVersion = AppVersion
	}
	m := &Model{
		Router:         mygoui.NewRouter("/home"),
		Home:           home,
		Cards:          DefaultCards(),
		ChartSmooth:    true,
		Sites:          DefaultSites(),
		Prefs:          DefaultPrefs(),
		IPLeft:         30,
		ShowNextUpdate: map[string]bool{},
		Unlocks:        DefaultUnlocks(),
	}
	m.normalize()
	return m
}

func (m *Model) normalize() {
	if m == nil {
		return
	}
	switch m.Home.Mode {
	case "rule", "global", "direct":
	default:
		m.Home.Mode = "rule"
	}
	if m.Prefs.Language == "" {
		m.Prefs = DefaultPrefs()
	}
	if m.ShowNextUpdate == nil {
		m.ShowNextUpdate = map[string]bool{}
	}
	if m.TunStack == "" {
		m.TunStack = "跟随订阅"
	}
	if m.Unlocks == nil {
		m.Unlocks = DefaultUnlocks()
	}
}

// View builds one frame of the main window.
func (m *Model) View(c *mygoui.Context) {
	if m == nil {
		return
	}
	m.normalize()
	if m.Router.Path() != "/rules" {
		m.Rules.Loaded = false
	}
	m.flushFilters(c.Now())
	dark := c.Theme().Dark
	if m.Prefs.ThemeMode == "system" && m.Hooks.SystemDark != nil {
		dark = m.Hooks.SystemDark()
	}
	switch m.Prefs.ThemeMode {
	case "light":
		dark = false
	case "dark":
		dark = true
	}
	pal := PaletteWithPrefs(dark, m.Prefs)
	theme := pal.Theme()
	if m.Prefs.FontFamily != "" {
		theme.Font = m.Prefs.FontFamily
	}
	c.SetTheme(theme)
	c.Root().Background(pal.Paper)
	mygoui.Row(c).Fill().AlignItems(mygoui.Stretch).Children(func() {
		m.sidebar(c, pal)
		mygoui.Column(c).Grow(1).FillHeight().Background(pal.Content).Children(func() {
			m.Router.View(c, func(r *mygoui.Route) {
				path := m.Router.Path()
				switch path {
				case "/home":
					r.Title("首页")
					m.homePage(c, pal)
				case "/proxies":
					r.Title("代理组")
					m.proxyPage(c, pal)
				case "/profile":
					r.Title("订阅")
					m.profilePage(c, pal)
				case "/settings":
					r.Title("设置")
					m.settingsPage(c, pal)
				case "/connections":
					r.Title("连接")
					m.connectionsPage(c, pal)
				case "/rules":
					r.Title("规则")
					m.rulesPage(c, pal)
				case "/logs":
					r.Title("日志")
					m.logsPage(c, pal)
				case "/unlock", "/test":
					r.Title("解锁测试")
					m.unlockPage(c, pal)
				default:
					page, ok := pageByPath(path)
					if !ok {
						r.Title("未找到")
						PlaceholderPage(c, "未找到", "这个页面还没有。")
						return
					}
					r.Title(page.Title)
					PlaceholderPage(c, page.Title, page.Body)
				}
			})
		})
	})
	m.overlay(c, pal)
}

func (m *Model) flushFilters(now time.Time) {
	for i := range m.Groups {
		g := &m.Groups[i]
		if g.FilterOpen && Debounced(now, g.FilterChanged, FilterDebounce) {
			g.FilterApplied = strings.TrimSpace(g.FilterText)
			g.FilterChanged = time.Time{}
		}
	}
}

func (m *Model) sidebarWidth() float32 {
	if m != nil && m.Prefs.CollapseNav {
		return sidebarCollapsedWidth
	}
	return sidebarExpandedWidth
}

func (m *Model) sidebar(c *mygoui.Context, pal Palette) {
	page := m.Router.Path()
	collapsed := m.Prefs.CollapseNav
	mygoui.Column(c).Width(m.sidebarWidth()).FillHeight().Background(pal.Paper).Label("sidebar").
		BorderWidth(0, 1, 0, 0).BorderColor(pal.Divider).Children(func() {
		m.logoRow(c, pal, collapsed)
		mygoui.Column(c).Grow(1).Padding(8, 10).Gap(4).Children(func() {
			for _, item := range Pages() {
				m.navItem(c, pal, item, page == item.Path, collapsed)
			}
		})
		if collapsed {
			return
		}
		mygoui.Row(c).Height(60).Padding(0, 16).Gap(12).AlignItems(mygoui.Center).
			BorderWidth(1, 0, 0, 0).BorderColor(pal.Divider).Children(func() {
			mygoui.Column(c).Gap(2).Children(func() {
				mygoui.Text(c, "↑ "+FormatSpeed(m.Home.UpSpeed)).FontSize(12).TextColor(pal.TextMuted)
				mygoui.Text(c, "↓ "+FormatSpeed(m.Home.DownSpeed)).FontSize(12).TextColor(pal.TextMuted)
			})
			mygoui.Spacer(c).Grow(1)
			mygoui.Text(c, sidebarStatus(m.Home)).FontSize(11).TextColor(pal.TextMuted)
		})
	})
}

func (m *Model) navItem(c *mygoui.Context, pal Palette, item Page, on, collapsed bool) {
	fg := pal.Text
	if on {
		fg = pal.SidebarOn
	}
	if collapsed {
		mygoui.Row(c).FillWidth().Justify(mygoui.Center).Children(func() {
			b := mygoui.ButtonBase(c.Key("nav-"+item.Path)).Size(52, 52).Radius(12).Label("nav-" + item.Nav)
			if on {
				b.Background(pal.SelectedFill())
			} else {
				b.Background(mygoui.Transparent)
			}
			b.TextColor(fg).AlignItems(mygoui.Center).Justify(mygoui.Center)
			b.Children(func() {
				mygoui.Icon(c, navIcon(item.ID)).Size(22, 22)
			})
			if b.Clicked() {
				m.Router.Push(item.Path)
			}
		})
		return
	}
	b := mygoui.ButtonBase(c.Key("nav-"+item.Path)).FillWidth().Height(40).Padding(0, 12).Gap(10).Radius(8).Label("nav-" + item.Nav)
	if on {
		b.Background(pal.SelectedFill())
	} else {
		b.Background(mygoui.Transparent)
	}
	b.TextColor(fg).AlignItems(mygoui.Center)
	b.Children(func() {
		mygoui.Icon(c, navIcon(item.ID)).Size(20, 20).Shrink(0)
		mygoui.Text(c, item.Nav).FontSize(14)
	})
	if b.Clicked() {
		m.Router.Push(item.Path)
	}
}

func (m *Model) logoRow(c *mygoui.Context, pal Palette, collapsed bool) {
	if collapsed {
		// Collapsed mark uses margin 0 and sits centered in the 56×56 logo area.
		mygoui.Row(c).Height(logoCollapsedBox).AlignItems(mygoui.Center).Justify(mygoui.Center).Children(func() {
			mygoui.Column(c).Size(logoCollapsedBox, logoCollapsedBox).Label("logo-slot").AlignItems(mygoui.Center).Justify(mygoui.Center).Children(func() {
				mygoui.Image(c, brandMark).Size(brandMarkSize, brandMarkSize).Label("netflow-mark")
			})
		})
		return
	}
	// Outer row is the sidebar logo slot. The inner row is Verge's 27px
	// line: the 36px mark uses margin -3/-3/5 so it sits against 「NetFlow」.
	mygoui.Row(c).Height(logoRowHeight).Padding(0, logoRowPaddingX).AlignItems(mygoui.Center).Children(func() {
		mygoui.Row(c).Height(logoInnerHeight).AlignItems(mygoui.Center).Children(func() {
			mygoui.Image(c, brandMark).Size(brandMarkSize, brandMarkSize).Shrink(0).
				Margin(brandMarkNudge, brandMarkMargin, 0, brandMarkNudge).Label("netflow-mark")
			mygoui.Text(c, "NetFlow").Bold().FontSize(16).TextColor(pal.Text)
		})
	})
}

func sidebarStatus(s HomeState) string {
	if s.Running {
		return "运行中"
	}
	return "已停止"
}

func (m *Model) goPath(path string) {
	if path == "/" {
		path = "/home"
	}
	m.Router.Push(path)
}

func (m *Model) setMode(mode string) {
	if m.Home.Mode == mode {
		return
	}
	prev := m.Home.Mode
	m.Home.Mode = mode
	if m.Hooks.SetMode != nil {
		if err := m.Hooks.SetMode(mode); err != nil {
			m.Home.Mode = prev
			m.Notice = err.Error()
		}
	}
}

func (m *Model) setProxy(on bool) {
	if on && !m.Home.Running {
		m.Home.SystemProxy = false
		m.Prefs.SystemProxy = false
		m.Notice = "内核尚未就绪，无法开启系统代理"
		return
	}
	prev := m.Home.SystemProxy
	m.Home.SystemProxy = on
	m.Prefs.SystemProxy = on
	if m.Hooks.SetSystemProxy != nil {
		if err := m.Hooks.SetSystemProxy(on); err != nil {
			m.Home.SystemProxy = prev
			m.Prefs.SystemProxy = prev
			m.Notice = err.Error()
			return
		}
	}
}

func (m *Model) setTUN(on bool) {
	if m.Busy == "tun" {
		return
	}
	if on && !m.Home.TUNAvailable {
		m.Notice = "TUN 暂不可用：需要特权服务或管理员权限"
		m.Home.TUN = false
		return
	}
	if m.Hooks.SetTUNAsync != nil {
		m.Busy = "tun"
		m.Notice = "正在切换虚拟网卡模式…"
		m.Hooks.SetTUNAsync(on, func(err error) {
			m.Busy = ""
			if err != nil {
				m.Notice = err.Error()
				return
			}
			m.Home.TUN, m.Prefs.TUN = on, on
			if m.Notice == "正在切换虚拟网卡模式…" {
				m.Notice = "虚拟网卡模式已更新"
			}
		})
		return
	}
	prev := m.Home.TUN
	m.Home.TUN = on
	m.Prefs.TUN = on
	if m.Hooks.SetTUN != nil {
		if err := m.Hooks.SetTUN(on); err != nil {
			m.Home.TUN = prev
			m.Prefs.TUN = prev
			m.Notice = err.Error()
		}
	}
}

func (m *Model) savePrefs() {
	if m.Hooks.SavePrefs != nil {
		if err := m.Hooks.SavePrefs(m.Prefs); err != nil {
			m.Notice = err.Error()
		}
	}
}

func (m *Model) setAutoLaunch(on bool) {
	if m.Hooks.SetAutoLaunch != nil {
		if err := m.Hooks.SetAutoLaunch(on); err != nil {
			m.Prefs.AutoLaunch = !on
			m.Home.AutoLaunch = !on
			m.Notice = err.Error()
			return
		}
	}
	m.Prefs.AutoLaunch = on
	m.Home.AutoLaunch = on
	m.savePrefs()
}

func (m *Model) setLightweight(on bool) {
	if m.Hooks.SetLightweight != nil {
		if err := m.Hooks.SetLightweight(on); err != nil {
			m.Notice = err.Error()
			return
		}
	} else {
		m.Prefs.Lightweight = on
		m.savePrefs()
	}
	if on {
		m.Notice = "已进入轻量模式"
	} else {
		m.Notice = "已退出轻量模式"
	}
}

func (m *Model) copy(text string) {
	if m.Hooks.Copy != nil {
		if err := m.Hooks.Copy(text); err != nil {
			m.Notice = "复制失败: " + err.Error()
			return
		}
	}
	m.Notice = "复制成功"
}

// CurrentItem is the active subscription, or nil.
func (m *Model) CurrentItem() *ProfileItem { return m.currentProfile() }

func (m *Model) currentProfile() *ProfileItem {
	for i := range m.Profiles {
		if m.Profiles[i].UID == m.CurrentProfile {
			return &m.Profiles[i]
		}
	}
	return nil
}

func (m *Model) subscriptionCount() int { return len(m.Profiles) }

func (m *Model) runMode() RunMode {
	if !m.Home.Running {
		return RunNotRunning
	}
	if m.Home.RunMode == "" {
		return RunSidecar
	}
	return m.Home.RunMode
}

func (m *Model) proxyAddr() string {
	if m.Home.ProxyAddr != "" {
		return m.Home.ProxyAddr
	}
	port := m.Home.MixedPort
	if port <= 0 {
		port = 7897
	}
	return "127.0.0.1:" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
