package app

import (
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/rules"
)

// coreEngine is the complete kernel surface used by the desktop app. Keeping
// it independent of the transport allows a privileged kernel process to be
// introduced without moving the UI or agent bridge into that process.
type coreEngine interface {
	SetTransformer(func([]byte, string) ([]byte, error))
	SetProfileID(string)
	ProfileID() string
	Start(string) error
	Reload() error
	Stop() error
	EffectiveConfig() ([]byte, error)
	Status() core.Status
	Select(string, string) error
	Selected(string) (string, error)
	Connections() ([]conn.Item, int64, int64)
	CloseConnection(string) error
	CloseExistingConnection(string) (bool, error)
	CloseAllConnections() error
	Rules() []rules.Item
	RuleProviders() []rules.Provider
	UpdateRuleProvider(string) error
	SubscribeLogs(func(string, string)) func()
	Group(string) (core.ProxyGroup, error)
	ProxyProviders() []core.ProxyProvider
	UpdateProxyProvider(string) error
	TestDelay(string, string, string, time.Duration) (int, error)
}

var _ coreEngine = (*core.Core)(nil)
var _ coreEngine = (*coreipc.Client)(nil)
