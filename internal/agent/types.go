package agent

import (
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type Profile struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Active              bool   `json:"active"`
	VergeArchive        bool   `json:"verge_archive_linked,omitempty"`
	VergeGlobalScript   bool   `json:"verge_global_script_enabled,omitempty"`
	VergeProfileScript  bool   `json:"verge_profile_script_enabled,omitempty"`
	VergeScriptRollback bool   `json:"verge_script_rollback_available,omitempty"`
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
	Profiles   []Profile `json:"profiles"`
	Total      int       `json:"total"`
	Offset     int       `json:"offset"`
	NextOffset int       `json:"next_offset"`
}

type PageArgs struct {
	Offset int `json:"offset,omitempty" jsonschema:"zero-based offset in the current list"`
	Limit  int `json:"limit,omitempty" jsonschema:"maximum items, 1 to 500; default 100"`
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
	WebDAV        bool      `json:"webdav" jsonschema:"explicitly upload automatic backups to saved WebDAV"`
	WebDAVPending int       `json:"webdav_pending" jsonschema:"automatic uploads awaiting completion"`
	WebDAVError   string    `json:"webdav_error,omitempty"`
	WebDAVRetry   time.Time `json:"webdav_retry,omitempty"`
	OnChange      bool      `json:"on_change" jsonschema:"also back up configuration changes; explicitly enabled"`
	Enabled       bool      `json:"enabled" jsonschema:"explicitly enable automatic local backups"`
	Directory     string    `json:"directory,omitempty" jsonschema:"existing absolute directory outside the configuration"`
	IntervalHours int       `json:"interval_hours,omitempty" jsonschema:"interval between 1 and 168 hours"`
	NextRun       time.Time `json:"next_run,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	NextRetry     time.Time `json:"next_retry,omitempty"`
}

type BackupWebDAVArgs struct {
	Enabled bool `json:"enabled" jsonschema:"explicitly enable automatic upload of unencrypted backups"`
}

type BackupOnChangeArgs struct {
	Enabled bool `json:"enabled" jsonschema:"explicitly enable backups on configuration changes"`
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
	ProfilesTotal        int           `json:"profiles_total"`
	ProfilesTruncated    bool          `json:"profiles_truncated"`
	ProfilesWarning      string        `json:"profiles_warning,omitempty"`
	Connections          []conn.Item   `json:"connections"`
	ConnectionsTotal     int           `json:"connections_total"`
	ConnectionsTruncated bool          `json:"connections_truncated"`
	ConnectionsWarning   string        `json:"connections_warning,omitempty"`
	Overrides            rewrite.State `json:"overrides"`
}

type ConnectionsArgs struct {
	Offset int `json:"offset,omitempty" jsonschema:"zero-based offset in the current live connection list"`
	Limit  int `json:"limit,omitempty" jsonschema:"maximum items, 1 to 500; default 100"`
}

type ConnectionsResult struct {
	Total       int         `json:"total"`
	Offset      int         `json:"offset"`
	NextOffset  int         `json:"next_offset"`
	Connections []conn.Item `json:"connections"`
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

// VergeScriptPreviewArgs explicitly opts into running archived scripts in a
// bounded guest for this read-only preview. It does not enable scripts.
type VergeScriptPreviewArgs struct {
	ProfileID string `json:"profile_id,omitempty" jsonschema:"subscription profile id; defaults to active profile"`
	Global    bool   `json:"global" jsonschema:"execute the archived global script"`
	Profile   bool   `json:"profile" jsonschema:"execute the archived subscription script"`
}
type VergeScriptPreview struct {
	PreviewID          string             `json:"preview_id"`
	Operation          string             `json:"operation"`
	TargetProfile      string             `json:"target_profile"`
	ChangedFields      []string           `json:"changed_fields"`
	OtherChangedFields int                `json:"other_changed_fields"`
	RulesBefore        PreviewRulesResult `json:"rules_before"`
	RulesAfter         PreviewRulesResult `json:"rules_after"`
	Warnings           []string           `json:"warnings"`
	ExpiresAt          time.Time          `json:"expires_at"`
}

// VergeScriptConfigArgs explicitly requests private configuration values.
type VergeScriptConfigArgs struct {
	PreviewID string `json:"preview_id" jsonschema:"unexpired script preview id"`
	Stage     string `json:"stage" jsonschema:"before or after"`
	Offset    int    `json:"offset,omitempty" jsonschema:"UTF-8 byte offset returned by the previous page"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum UTF-8 bytes per page, default and maximum 65536"`
}
type VergeScriptConfigPage struct {
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset"`
	Total      int    `json:"total"`
	Text       string `json:"text"`
}

type VergeScriptApplyResult struct {
	Applied     bool     `json:"applied"`
	Active      bool     `json:"active"`
	CoreRunning bool     `json:"core_running"`
	Warnings    []string `json:"warnings,omitempty"`
}

type VergeScriptCachePruneResult struct {
	Removed int   `json:"removed"`
	Bytes   int64 `json:"bytes"`
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

// ChainHop identifies a resolved member of a visible proxy group.
type ChainHop struct {
	Name     string `json:"name" jsonschema:"resolved proxy node name"`
	Provider string `json:"provider,omitempty" jsonschema:"provider identity, omitted for inline proxies"`
	Group    string `json:"group" jsonschema:"group currently containing the node"`
}
type ChainPreviewArgs struct {
	Target string     `json:"target" jsonschema:"selectable target group; GLOBAL is used in global mode"`
	Hops   []ChainHop `json:"hops" jsonschema:"two to eight nodes, from entry to exit"`
}
type ChainPreview struct {
	ProposalID string     `json:"proposal_id"`
	ProfileID  string     `json:"profile_id"`
	Target     string     `json:"target"`
	Hops       []ChainHop `json:"hops"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Warnings   []string   `json:"warnings"`
}
type ChainStatus struct {
	Configured bool       `json:"configured"`
	Warning    string     `json:"warning,omitempty"`
	Active     bool       `json:"active"`
	ProfileID  string     `json:"profile_id,omitempty"`
	Target     string     `json:"target,omitempty"`
	Hops       []ChainHop `json:"hops,omitempty"`
}

type ProxyNode struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider,omitempty"`
	DialerProxy string `json:"dialer_proxy,omitempty"`
	UDP         bool   `json:"udp"`
}
type ProxyGroup struct {
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	Current        string      `json:"current"`
	Nodes          []ProxyNode `json:"nodes"`
	NodesTotal     int         `json:"nodes_total"`
	NodesTruncated bool        `json:"nodes_truncated"`
	NodesWarning   string      `json:"nodes_warning,omitempty"`
}
type GroupsResult struct {
	Groups     []ProxyGroup `json:"groups"`
	Total      int          `json:"total"`
	Offset     int          `json:"offset"`
	NextOffset int          `json:"next_offset"`
}

type GroupNodesArgs struct {
	Group  string `json:"group" jsonschema:"proxy group name"`
	Offset int    `json:"offset,omitempty" jsonschema:"zero-based member offset"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum members, 1 to 500; default 100"`
}
type GroupNodesResult struct {
	Group      string      `json:"group"`
	Total      int         `json:"total"`
	Offset     int         `json:"offset"`
	NextOffset int         `json:"next_offset"`
	Nodes      []ProxyNode `json:"nodes"`
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
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset"`
	Rules      []Rule `json:"rules"`
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
	Proxy           []ProviderInfo `json:"proxy"`
	Rule            []ProviderInfo `json:"rule"`
	ProxyTotal      int            `json:"proxy_total"`
	ProxyNextOffset int            `json:"proxy_next_offset"`
	RuleTotal       int            `json:"rule_total"`
	RuleNextOffset  int            `json:"rule_next_offset"`
}

type ProviderPageArgs struct {
	Kind   string `json:"kind" jsonschema:"proxy or rule"`
	Offset int    `json:"offset,omitempty" jsonschema:"zero-based offset"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum providers, 1 to 500; default 100"`
}
type ProviderPageResult struct {
	Kind       string         `json:"kind"`
	Total      int            `json:"total"`
	Offset     int            `json:"offset"`
	NextOffset int            `json:"next_offset"`
	Providers  []ProviderInfo `json:"providers"`
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
