package agent

import (
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// KernelOptionsResult contains explicit overrides; omitted fields inherit the
// active subscription and do not necessarily reflect its effective values.
type KernelOptionsResult struct {
	Overrides kernelopts.Options `json:"overrides"`
	Effective *KernelEffective   `json:"effective,omitempty"`
}

// KernelEffective is an allowlisted live-kernel snapshot without paths or secrets.
type KernelEffective struct {
	Mode         string `json:"mode"`
	AllowLAN     bool   `json:"allow_lan"`
	IPv6         bool   `json:"ipv6"`
	UnifiedDelay bool   `json:"unified_delay"`
	LogLevel     string `json:"log_level"`
	MixedPort    int    `json:"mixed_port"`
	SOCKSPort    int    `json:"socks_port"`
	HTTPPort     int    `json:"http_port"`
}

type KernelOptionArgs struct {
	Name        string  `json:"name" jsonschema:"allow-lan, ipv6, unified-delay, log-level, tun-stack, mixed-port, socks-port, or http-port"`
	Inherit     bool    `json:"inherit,omitempty" jsonschema:"remove this override and inherit the subscription value"`
	BoolValue   *bool   `json:"bool_value,omitempty" jsonschema:"value for boolean options"`
	StringValue *string `json:"string_value,omitempty" jsonschema:"value for log-level or tun-stack"`
	PortValue   *int    `json:"port_value,omitempty" jsonschema:"listener port; 0 disables socks-port or http-port"`
}

type ProfileList struct {
	Profiles []Profile `json:"profiles"`
}

type ProfileImportArgs struct {
	URL            string `json:"url" jsonschema:"HTTP or HTTPS subscription URL, which may contain credentials"`
	Name           string `json:"name,omitempty" jsonschema:"optional display name"`
	Description    string `json:"description,omitempty" jsonschema:"optional user-provided description"`
	UserAgent      string `json:"user_agent,omitempty" jsonschema:"optional HTTP user agent"`
	Timeout        int    `json:"timeout_seconds,omitempty" jsonschema:"download timeout from 1 to 300 seconds, default 60"`
	Interval       int    `json:"update_interval_minutes,omitempty" jsonschema:"automatic update interval from 1 to 43200 minutes, default 1440"`
	AutoUpdate     bool   `json:"auto_update,omitempty" jsonschema:"enable periodic updates"`
	UseCoreProxy   bool   `json:"use_core_proxy,omitempty" jsonschema:"download through the running core; never fall back to direct"`
	UseSystemProxy bool   `json:"use_system_proxy,omitempty" jsonschema:"use the manual system proxy when core proxy is not selected"`
	AllowInsecure  bool   `json:"allow_insecure,omitempty" jsonschema:"explicitly allow untrusted TLS certificates for this subscription"`
}

// ProfileSettings omits the subscription URL and internal file paths. User
// supplied names, descriptions and user agents may themselves be sensitive.
type ProfileSettings struct {
	ProfileID      string `json:"profile_id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	Type           string `json:"type"`
	Active         bool   `json:"active"`
	UserAgent      string `json:"user_agent,omitempty"`
	Timeout        int    `json:"timeout_seconds,omitempty"`
	Interval       int    `json:"update_interval_minutes,omitempty"`
	AutoUpdate     bool   `json:"auto_update"`
	UseCoreProxy   bool   `json:"use_core_proxy"`
	UseSystemProxy bool   `json:"use_system_proxy"`
	AllowInsecure  bool   `json:"allow_insecure"`
}

type ProfileSettingsPatch struct {
	ProfileID      string  `json:"profile_id" jsonschema:"existing profile id"`
	Name           *string `json:"name,omitempty" jsonschema:"optional replacement display name"`
	Description    *string `json:"description,omitempty" jsonschema:"optional replacement description"`
	UserAgent      *string `json:"user_agent,omitempty" jsonschema:"optional replacement user agent"`
	Timeout        *int    `json:"timeout_seconds,omitempty" jsonschema:"download timeout from 1 to 300 seconds"`
	Interval       *int    `json:"update_interval_minutes,omitempty" jsonschema:"automatic update interval from 1 to 43200 minutes"`
	AutoUpdate     *bool   `json:"auto_update,omitempty" jsonschema:"enable periodic updates"`
	UseCoreProxy   *bool   `json:"use_core_proxy,omitempty" jsonschema:"use the running core for downloads"`
	UseSystemProxy *bool   `json:"use_system_proxy,omitempty" jsonschema:"use the manual system proxy if core proxy is not selected"`
	AllowInsecure  *bool   `json:"allow_insecure,omitempty" jsonschema:"explicitly allow untrusted TLS certificates"`
}

type ProfileURLArgs struct {
	ProfileID string `json:"profile_id" jsonschema:"existing remote profile id"`
	URL       string `json:"url" jsonschema:"replacement HTTP or HTTPS subscription URL, which may contain credentials"`
}

type ProfileJob struct {
	JobID     string    `json:"job_id"`
	Operation string    `json:"operation"`
	ProfileID string    `json:"profile_id,omitempty"`
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type ProfileJobArgs struct {
	JobID string `json:"job_id" jsonschema:"profile job identifier"`
}

type BackupArgs struct {
	Path string `json:"path" jsonschema:"absolute new ZIP path outside the configuration directory"`
}

type BackupJob struct {
	JobID       string    `json:"job_id"`
	Operation   string    `json:"operation"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	RemoteName  string    `json:"remote_name,omitempty"`
	RemoteNames []string  `json:"remote_names,omitempty"`
}

type RestoreArgs struct {
	Archive     string `json:"archive" jsonschema:"absolute path to an existing NetFlow ZIP backup"`
	Destination string `json:"destination" jsonschema:"absolute path to a new directory outside the running configuration"`
}

type BackupJobArgs struct {
	JobID string `json:"job_id" jsonschema:"backup job identifier"`
}

type BackupSchedule struct {
	Enabled       bool      `json:"enabled" jsonschema:"explicitly enable automatic local backups"`
	Directory     string    `json:"directory,omitempty" jsonschema:"existing absolute directory outside the configuration"`
	IntervalHours int       `json:"interval_hours,omitempty" jsonschema:"interval between 1 and 168 hours"`
	NextRun       time.Time `json:"next_run,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	NextRetry     time.Time `json:"next_retry,omitempty"`
}

type BackupScheduleArgs struct {
	Enabled       bool   `json:"enabled" jsonschema:"explicitly enable automatic local backups"`
	Directory     string `json:"directory,omitempty" jsonschema:"existing absolute directory outside the configuration"`
	IntervalHours int    `json:"interval_hours,omitempty" jsonschema:"interval between 1 and 168 hours"`
}

type WebDAVUploadArgs struct {
	Archive  string `json:"archive" jsonschema:"absolute path to an existing unencrypted local backup ZIP"`
	URL      string `json:"url,omitempty" jsonschema:"HTTPS WebDAV collection URL; may contain secrets"`
	User     string `json:"user,omitempty" jsonschema:"optional WebDAV username"`
	Password string `json:"password,omitempty" jsonschema:"optional WebDAV password"`
	UseSaved bool   `json:"use_saved,omitempty" jsonschema:"use existing saved WebDAV credentials instead of providing credentials"`
}

type WebDAVRestoreArgs struct {
	RemoteName  string `json:"remote_name" jsonschema:"generated WebDAV backup filename returned by an upload job"`
	Destination string `json:"destination" jsonschema:"absolute path to a new directory outside the running configuration"`
	URL         string `json:"url,omitempty" jsonschema:"HTTPS WebDAV collection URL; may contain secrets"`
	User        string `json:"user,omitempty" jsonschema:"optional WebDAV username"`
	Password    string `json:"password,omitempty" jsonschema:"optional WebDAV password"`
	UseSaved    bool   `json:"use_saved,omitempty" jsonschema:"use existing saved WebDAV credentials instead of supplying credentials"`
}

type WebDAVListArgs struct {
	URL      string `json:"url,omitempty" jsonschema:"HTTPS WebDAV collection URL; may contain secrets"`
	User     string `json:"user,omitempty" jsonschema:"optional WebDAV username"`
	Password string `json:"password,omitempty" jsonschema:"optional WebDAV password"`
	UseSaved bool   `json:"use_saved,omitempty" jsonschema:"use existing saved WebDAV credentials"`
}

type WebDAVConfigArgs struct {
	URL      string `json:"url" jsonschema:"HTTPS WebDAV collection URL; may contain secrets"`
	User     string `json:"user,omitempty" jsonschema:"optional WebDAV username"`
	Password string `json:"password,omitempty" jsonschema:"optional WebDAV password"`
}

type WebDAVConfigStatus struct {
	Saved                     bool `json:"saved"`
	ProtectedStorageAvailable bool `json:"protected_storage_available"`
}
type Status struct {
	Running              bool          `json:"running"`
	Headless             bool          `json:"headless"`
	TUN                  bool          `json:"tun"`
	TUNPending           bool          `json:"tun_pending"`
	TUNError             string        `json:"tun_error,omitempty"`
	GeoPending           bool          `json:"geo_pending"`
	GeoError             string        `json:"geo_error,omitempty"`
	GeoRestart           bool          `json:"geo_restart_required"`
	ProviderCacheWarning string        `json:"provider_cache_warning,omitempty"`
	RewriteWarning       string        `json:"rewrite_warning,omitempty"`
	KernelOptionsWarning string        `json:"kernel_options_warning,omitempty"`
	SettingsWarning      string        `json:"settings_warning,omitempty"`
	TUNStacks            []string      `json:"tun_stacks"`
	Mode                 string        `json:"mode"`
	ActiveProfile        string        `json:"active_profile,omitempty"`
	Revision             uint64        `json:"revision"`
	Profiles             []Profile     `json:"profiles"`
	Connections          []conn.Item   `json:"connections"`
	Overrides            rewrite.State `json:"overrides"`
}

// Diagnostics deliberately excludes configuration contents, paths, profile
// names and URLs, endpoint credentials, and connection metadata.
type Diagnostics struct {
	SchemaVersion          int    `json:"schema_version"`
	AppVersion             string `json:"app_version"`
	CoreVersion            string `json:"core_version"`
	OS                     string `json:"os"`
	Architecture           string `json:"architecture"`
	GoVersion              string `json:"go_version"`
	CoreRunning            bool   `json:"core_running"`
	Headless               bool   `json:"headless"`
	CoreHasError           bool   `json:"core_has_error"`
	Mode                   string `json:"mode"`
	TUN                    bool   `json:"tun"`
	TUNPending             bool   `json:"tun_pending"`
	TUNHasError            bool   `json:"tun_has_error"`
	PrivilegedKernel       bool   `json:"privileged_kernel"`
	ProfileCatalogReadable bool   `json:"profile_catalog_readable"`
	ProfileCount           int    `json:"profile_count"`
	ConnectionCount        int    `json:"connection_count"`
	RewriteRevision        uint64 `json:"rewrite_revision"`
	UptimeSeconds          int64  `json:"uptime_seconds"`
}

type Change struct {
	Scope         string        `json:"scope" jsonschema:"global, profile, or connection"`
	Operation     string        `json:"operation" jsonschema:"set or clear"`
	ProfileID     string        `json:"profile_id,omitempty" jsonschema:"profile id for profile scope"`
	Layer         rewrite.Layer `json:"layer,omitempty" jsonschema:"rule changes for global or profile scope"`
	ConnectionID  string        `json:"connection_id,omitempty" jsonschema:"active connection id for connection scope"`
	Policy        string        `json:"policy,omitempty" jsonschema:"existing proxy policy for connection scope"`
	TTLSeconds    int           `json:"ttl_seconds,omitempty" jsonschema:"connection override lifetime in seconds, between 1 and 86400"`
	CloseExisting bool          `json:"close_existing,omitempty" jsonschema:"close the selected existing connection after applying a connection override"`
}

type RewriteHistory struct {
	Entries []rewrite.HistoryItem `json:"entries"`
}

type ClearRewriteHistoryResult struct {
	Revision uint64 `json:"revision"`
}

type RollbackArgs struct {
	Revision      *uint64 `json:"revision" jsonschema:"historical stored revision to preview"`
	Scope         string  `json:"scope" jsonschema:"global, profile, or connection"`
	ProfileID     string  `json:"profile_id,omitempty" jsonschema:"profile id for profile scope"`
	ConnectionID  string  `json:"connection_id,omitempty" jsonschema:"connection id for connection scope"`
	CloseExisting bool    `json:"close_existing,omitempty" jsonschema:"optionally close the selected existing connection after applying a restored matcher"`
}

type Preview struct {
	ProposalID           string    `json:"proposal_id"`
	Revision             uint64    `json:"revision"`
	ActiveProfile        string    `json:"active_profile,omitempty"`
	TargetProfile        string    `json:"target_profile,omitempty"`
	RulesBefore          []string  `json:"rules_before"`
	RulesAfter           []string  `json:"rules_after"`
	RulesBeforeTotal     int       `json:"rules_before_total"`
	RulesAfterTotal      int       `json:"rules_after_total"`
	RulesBeforeTruncated bool      `json:"rules_before_truncated,omitempty"`
	RulesAfterTruncated  bool      `json:"rules_after_truncated,omitempty"`
	Warnings             []string  `json:"warnings,omitempty"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type PreviewRulesArgs struct {
	ProposalID string `json:"proposal_id" jsonschema:"unexpired proposal id"`
	Stage      string `json:"stage" jsonschema:"before or after"`
	Offset     int    `json:"offset,omitempty" jsonschema:"zero-based rule offset"`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum rules to return, 1 to 500, default 100"`
}

type PreviewRulesResult struct {
	Total      int      `json:"total"`
	Offset     int      `json:"offset"`
	NextOffset int      `json:"next_offset"`
	Rules      []string `json:"rules"`
}

type ApplyArgs struct {
	ProposalID string `json:"proposal_id" jsonschema:"proposal id returned by preview"`
}
type ApplyResult struct {
	Revision         uint64   `json:"revision"`
	Active           bool     `json:"active"`
	ClosedConnection bool     `json:"closed_connection"`
	Warnings         []string `json:"warnings,omitempty"`
}

type ProxyNode struct {
	Name string `json:"name"`
	Type string `json:"type"`
	UDP  bool   `json:"udp"`
}
type ProxyGroup struct {
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Current string      `json:"current"`
	Nodes   []ProxyNode `json:"nodes"`
}
type GroupsResult struct {
	Groups []ProxyGroup `json:"groups"`
}
type SelectArgs struct {
	Group string `json:"group" jsonschema:"proxy group name"`
	Node  string `json:"node" jsonschema:"member name"`
}
type ModeArgs struct {
	Mode string `json:"mode" jsonschema:"rule, global, or direct"`
}
type ProfileArgs struct {
	ProfileID string `json:"profile_id" jsonschema:"profile id"`
}
type ConnectionArgs struct {
	ConnectionID string `json:"connection_id" jsonschema:"active connection id"`
}
type ActionResult struct {
	OK       bool     `json:"ok"`
	Warnings []string `json:"warnings,omitempty"`
}
type CloseResult struct {
	Closed bool `json:"closed"`
}
type MigrationPath struct {
	Path string `json:"path" jsonschema:"absolute path to a Clash Verge directory or backup ZIP"`
}
type RulesArgs struct {
	Offset int `json:"offset,omitempty" jsonschema:"zero-based offset"`
	Limit  int `json:"limit,omitempty" jsonschema:"page size, 1 to 500; default 100"`
}
type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Policy  string `json:"policy"`
}
type RulesResult struct {
	Total  int    `json:"total"`
	Offset int    `json:"offset"`
	Rules  []Rule `json:"rules"`
}

// TunArgs requests a user-visible TUN transition. Enabling may prompt for UAC.
type TunArgs struct {
	Enabled *bool `json:"enabled" jsonschema:"true to enable TUN, false to disable"`
}
type TunResult struct {
	Accepted bool `json:"accepted"`
	Pending  bool `json:"pending"`
	TUN      bool `json:"tun"`
}

type TunAutoStartResult struct {
	Enabled   bool   `json:"enabled"`
	AppliesTo string `json:"applies_to"`
}

type GeoResult struct {
	Accepted bool `json:"accepted"`
	Pending  bool `json:"pending"`
}

// Provider summaries deliberately omit provider URLs and local file paths.
type ProviderInfo struct {
	Name     string `json:"name"`
	Vehicle  string `json:"vehicle"`
	Behavior string `json:"behavior,omitempty"`
	Count    int    `json:"count"`
}
type ProviderList struct {
	Proxy []ProviderInfo `json:"proxy"`
	Rule  []ProviderInfo `json:"rule"`
}
type ProviderUpdateArgs struct {
	Kind string `json:"kind" jsonschema:"proxy or rule"`
	Name string `json:"name" jsonschema:"provider name"`
}
type ProviderJobArgs struct {
	JobID string `json:"job_id" jsonschema:"provider update job id"`
}
type ProviderJob struct {
	JobID     string    `json:"job_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	ProfileID string    `json:"profile_id,omitempty"`
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
