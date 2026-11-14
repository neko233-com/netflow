package agent

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/neko233-com/netflow"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/migration"
)

type Empty struct{}

// NewMCP exposes a two-step preview/apply interface over the authenticated
// local bridge. No subscription URLs, core secrets, or token are returned.
func NewMCP(client Client) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netflow", Version: netflow.Version()}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_verge_script", Description: "Run selected archived Clash Verge scripts in a bounded guest and validate the configuration offline. Select neither script to preview disabling them. Preview does not apply; inspect all rule pages, full config and warnings.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in VergeScriptPreviewArgs) (*mcp.CallToolResult, VergeScriptPreview, error) {
		var out VergeScriptPreview
		c := client
		if c.Timeout <= 0 {
			c.Timeout = 60 * time.Second
		}
		err := c.Call(ctx, "verge-script-preview", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_verge_script_rollback", Description: "Preview and validate the previous approved script setting, without rerunning JavaScript or changing routing.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileArgs) (*mcp.CallToolResult, VergeScriptPreview, error) {
		var out VergeScriptPreview
		c := client
		if c.Timeout <= 0 {
			c.Timeout = 60 * time.Second
		}
		err := c.Call(ctx, "verge-script-rollback-preview", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_verge_subscription_update", Description: "Download a remote subscription, optionally from a replacement URL, with its saved network options; run its approved Verge scripts and validate without applying. Inspect rules, configuration and warnings before separately applying.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in VergeScriptUpdateArgs) (*mcp.CallToolResult, VergeScriptPreview, error) {
		var out VergeScriptPreview
		c := client
		if c.Timeout <= 0 {
			c.Timeout = 6 * time.Minute
		}
		err := c.Call(ctx, "verge-script-update-preview", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_apply_verge_script", Description: "Apply an unexpired, validated script preview. This can reload the kernel and change routing; the previous setting can be previewed for rollback."}, func(ctx context.Context, _ *mcp.CallToolRequest, in ApplyArgs) (*mcp.CallToolResult, VergeScriptApplyResult, error) {
		var out VergeScriptApplyResult
		c := client
		if c.Timeout <= 0 {
			c.Timeout = 60 * time.Second
		}
		err := c.Call(ctx, "verge-script-apply", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_prune_verge_script_cache", Description: "Delete unreferenced NetFlow-managed script outputs and retained subscription snapshots; current and previous settings are retained."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, VergeScriptCachePruneResult, error) {
		var out VergeScriptCachePruneResult
		c := client
		if c.Timeout <= 0 {
			c.Timeout = 90 * time.Second
		}
		err := c.Call(ctx, "verge-script-cache-prune", Empty{}, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_verge_script_preview_rules", Description: "Page through before or after rules of a read-only Verge script preview. Pass the preview_id as proposal_id.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in PreviewRulesArgs) (*mcp.CallToolResult, PreviewRulesResult, error) {
		var out PreviewRulesResult
		err := client.Call(ctx, "verge-script-preview-rules", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_verge_script_preview_config", Description: "Explicitly reveal a UTF-8 byte page of the full before or after configuration for a script preview. The returned text can include subscription credentials and other private data. Follow next_offset until total.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in VergeScriptConfigArgs) (*mcp.CallToolResult, VergeScriptConfigPage, error) {
		var out VergeScriptConfigPage
		err := client.Call(ctx, "verge-script-preview-config", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_cancel_verge_script_preview", Description: "Discard a read-only Verge script preview and its stored rules. Pass the preview_id as proposal_id."}, func(ctx context.Context, _ *mcp.CallToolRequest, in ApplyArgs) (*mcp.CallToolResult, ActionResult, error) {
		var out ActionResult
		err := client.Call(ctx, "verge-script-preview-cancel", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_status", Description: "List core status, profiles, a bounded first page of active connections, and agent-managed rewrite state. Subscription URLs are omitted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Status, error) {
			var out Status
			err := client.Call(ctx, "status", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_connections", Description: "Page through active connections sorted by ID. Each request sees a fresh live snapshot, so connections opening or closing can shift offsets; pages may be shorter than requested. Use next_offset.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ConnectionsArgs) (*mcp.CallToolResult, ConnectionsResult, error) {
			var out ConnectionsResult
			err := client.Call(ctx, "connections", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_diagnostics", Description: "Return an allowlisted diagnostics summary without subscription URLs, file paths, error text, tokens, or connection metadata.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Diagnostics, error) {
			var out Diagnostics
			err := client.Call(ctx, "diagnostics", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_kernel_options", Description: "Read explicit kernel overrides and an allowlisted live-kernel snapshot. Omitted overrides inherit the active subscription.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, KernelOptionsResult, error) {
			var out KernelOptionsResult
			err := client.Call(ctx, "kernel-options", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_set_kernel_option", Description: "Change one kernel override, or explicitly inherit it from the subscription. Validates and reloads the core; failure attempts rollback. May interrupt connections and affect routing or listening ports."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in KernelOptionArgs) (*mcp.CallToolResult, KernelOptionsResult, error) {
			var out KernelOptionsResult
			err := client.Call(ctx, "kernel-option", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_shutdown_headless", Description: "Stop a headless NetFlow instance and restore its TUN routes. GUI instances reject this request."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "shutdown", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_set_tun", Description: "Request TUN on or off; enabling may show a Windows administrator consent prompt. If pending, poll netflow_status for tun_pending and tun_error."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TunArgs) (*mcp.CallToolResult, TunResult, error) {
			var out TunResult
			err := client.Call(ctx, "tun", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_tun_autostart", Description: "Read whether a future GUI launch requests TUN automatically; headless serve uses its own --tun option.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, TunAutoStartResult, error) {
			var out TunAutoStartResult
			err := client.Call(ctx, "tun-autostart", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_set_tun_autostart", Description: "Set whether future GUI launches request TUN. Does not change current TUN; future launches still perform conflict checks and may request administrator consent."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TunArgs) (*mcp.CallToolResult, TunAutoStartResult, error) {
			var out TunAutoStartResult
			err := client.Call(ctx, "tun-autostart-set", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_update_geodata", Description: "Download existing GeoData databases through the active local proxy. Poll netflow_status for geo_pending, geo_error and geo_restart_required; updates apply after restarting NetFlow."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, GeoResult, error) {
			var out GeoResult
			err := client.Call(ctx, "update-geo", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_rewrite", Description: "Preview a global, subscription profile, or time-limited connection-matcher rule rewrite. Returns a short-lived proposal; changes do not apply until netflow_apply_rewrite. Existing connections are not rerouted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, change Change) (*mcp.CallToolResult, Preview, error) {
			var out Preview
			err := client.Call(ctx, "preview", change, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_rules", Description: "Page through all before or after rules of an unexpired preview. Use next_offset until it equals total; pages may be shorter than the requested limit.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in PreviewRulesArgs) (*mcp.CallToolResult, PreviewRulesResult, error) {
			var out PreviewRulesResult
			err := client.Call(ctx, "preview-rules", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_cancel_preview", Description: "Discard an unexpired proposal without applying it, releasing its stored preview rules."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ApplyArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "cancel-preview", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_rewrite_history", Description: "List bounded stored rewrite-state revision summaries, newest first. History may include a state whose kernel reload failed.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, RewriteHistory, error) {
			var out RewriteHistory
			err := client.Call(ctx, "rewrite-history", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_clear_rewrite_history", Description: "Delete stored rewrite history without changing current rules; invalidates pending proposals when history was present.", Annotations: &mcp.ToolAnnotations{DestructiveHint: func() *bool { b := true; return &b }()}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ClearRewriteHistoryResult, error) {
			var out ClearRewriteHistoryResult
			err := client.Call(ctx, "clear-rewrite-history", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_rollback", Description: "Preview and validate one global, profile or connection scope from a stored rewrite revision. The result must be explicitly applied with netflow_apply_rewrite. Expired or changed connection matchers cannot be restored.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in RollbackArgs) (*mcp.CallToolResult, Preview, error) {
			var out Preview
			err := client.Call(ctx, "rollback-preview", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_apply_rewrite", Description: "Apply an unexpired preview proposal if its configuration and revision are unchanged. This changes network routing; an explicitly requested connection close may interrupt that connection.", Annotations: &mcp.ToolAnnotations{}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ApplyArgs) (*mcp.CallToolResult, ApplyResult, error) {
			var out ApplyResult
			err := client.Call(ctx, "apply", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_chain_status", Description: "Read the active session-only proxy chain. Target groups use the chain for new connections; existing connections are not rerouted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ChainStatus, error) {
		var out ChainStatus
		err := client.Call(ctx, "chain-status", nil, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_preview_chain", Description: "Validate two to eight resolved proxy nodes and preview a session-only chain without changing routing. Apply the returned proposal separately.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in ChainPreviewArgs) (*mcp.CallToolResult, ChainPreview, error) {
		var out ChainPreview
		err := client.Call(ctx, "chain-preview", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_apply_chain", Description: "Apply an unexpired chain preview if configuration and sources remain unchanged. This changes routing for new connections."}, func(ctx context.Context, _ *mcp.CallToolRequest, in ApplyArgs) (*mcp.CallToolResult, ChainStatus, error) {
		var out ChainStatus
		err := client.Call(ctx, "chain-apply", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_cancel_chain_preview", Description: "Discard a pending chain preview."}, func(ctx context.Context, _ *mcp.CallToolRequest, in ApplyArgs) (*mcp.CallToolResult, ActionResult, error) {
		var out ActionResult
		err := client.Call(ctx, "chain-cancel-preview", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_disconnect_chain", Description: "Disconnect the current chain and restore the target group's previous selection. Existing connections are not rerouted."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ActionResult, error) {
		var out ActionResult
		err := client.Call(ctx, "chain-disconnect", nil, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_proxy_groups", Description: "Page live proxy groups with a bounded first page of members. Use next_offset; groups may change after reload.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in PageArgs) (*mcp.CallToolResult, GroupsResult, error) {
			var out GroupsResult
			err := client.Call(ctx, "groups", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_proxy_group_nodes", Description: "Page live members of a named proxy group. Use next_offset; membership can change between requests.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in GroupNodesArgs) (*mcp.CallToolResult, GroupNodesResult, error) {
			var out GroupNodesResult
			err := client.Call(ctx, "group-nodes", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_profiles", Description: "Page profile IDs, user-controlled names and active state without subscription URLs. Use next_offset; the catalog can change.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in PageArgs) (*mcp.CallToolResult, ProfileList, error) {
			var out ProfileList
			err := client.Call(ctx, "profiles", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_profile_settings", Description: "Read user-provided profile metadata and download options without the subscription URL. Names, descriptions and user agents can themselves contain sensitive text.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileArgs) (*mcp.CallToolResult, ProfileSettings, error) {
			var out ProfileSettings
			err := client.Call(ctx, "profile-settings", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_update_profile_settings", Description: "Update selected profile metadata or remote download options without changing its subscription URL. New options affect future downloads; enabling insecure TLS or a proxy is explicit."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileSettingsPatch) (*mcp.CallToolResult, ProfileSettings, error) {
			var out ProfileSettings
			err := client.Call(ctx, "profile-settings-set", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_replace_profile_url", Description: "Fetch and validate a replacement subscription URL before applying it. The URL may contain credentials; the asynchronous job does not return it. Poll netflow_profile_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileURLArgs) (*mcp.CallToolResult, ProfileJob, error) {
			var out ProfileJob
			err := client.Call(ctx, "profile-url-set", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_config", Description: "Read whether WebDAV credentials are saved and account-protected storage is available. Never returns credential values.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args Empty) (*mcp.CallToolResult, WebDAVConfigStatus, error) {
			var out WebDAVConfigStatus
			err := client.Call(ctx, "webdav-config", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_save", Description: "Explicitly replace saved WebDAV credentials using account-protected storage. Does not connect to the server; fails when protected storage is unavailable."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args WebDAVConfigArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "webdav-save", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_clear", Description: "Permanently delete the saved WebDAV address and credentials. Does not delete remote backups."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args Empty) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "webdav-clear", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_list", Description: "Read generated backup filenames from an HTTPS WebDAV collection; poll netflow_backup_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args WebDAVListArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "webdav-list", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_upload", Description: "Explicitly upload a chosen local backup ZIP to an HTTPS WebDAV collection. The backup is unencrypted and may contain credentials. A failed or interrupted upload may leave an incomplete remote file. Poll netflow_backup_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args WebDAVUploadArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "webdav-upload", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_webdav_restore", Description: "Download a generated WebDAV backup over HTTPS, validate it, and restore to a new directory outside the active configuration. A failure may leave a partial destination. Poll netflow_backup_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args WebDAVRestoreArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "webdav-restore", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_schedule", Description: "Read the automatic local backup schedule.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args Empty) (*mcp.CallToolResult, BackupSchedule, error) {
			var out BackupSchedule
			err := client.Call(ctx, "backup-schedule", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_schedule_set", Description: "Explicitly enable or disable periodic unencrypted local backups while the app is running. Backups contain credentials. At most 30 app-named archives are retained; no archive is deleted automatically."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args BackupScheduleArgs) (*mcp.CallToolResult, BackupSchedule, error) {
			var out BackupSchedule
			err := client.Call(ctx, "backup-schedule-set", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_webdav", Description: "Explicitly enable or disable automatic WebDAV uploads for a local backup schedule. Requires saved account-protected credentials. Unencrypted backups may contain credentials; failed uploads can leave partial or duplicate remote files. Disabling discards queued uploads but does not delete files."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args BackupWebDAVArgs) (*mcp.CallToolResult, BackupSchedule, error) {
			var out BackupSchedule
			err := client.Call(ctx, "backup-webdav", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_on_change", Description: "Explicitly enable or disable backups on configuration changes for an existing local schedule. Enabling creates an initial unencrypted snapshot; scans occur while running, with periodic content reconciliation. The 30 archive limit applies."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args BackupOnChangeArgs) (*mcp.CallToolResult, BackupSchedule, error) {
			var out BackupSchedule
			err := client.Call(ctx, "backup-on-change", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_create", Description: "Create an unencrypted local backup while NetFlow is running. It contains subscription credentials, excludes volatile caches and logs, and fails if configuration changes during capture. Poll netflow_backup_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args BackupArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "backup-create", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_backup_job_status", Description: "Read a running local backup job. Completed jobs are kept for up to ten minutes, subject to capacity.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args BackupJobArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "backup-job-status", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_restore_backup", Description: "Validate a local NetFlow backup and restore it into a new directory outside the active configuration. It never overwrites an existing destination. Poll netflow_backup_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args RestoreArgs) (*mcp.CallToolResult, BackupJob, error) {
			var out BackupJob
			err := client.Call(ctx, "restore-create", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_import_profile", Description: "Start an asynchronous subscription import. The URL may contain credentials and is not returned in job results. Poll netflow_profile_job_status and inspect profiles before retrying a failed import."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProfileImportArgs) (*mcp.CallToolResult, ProfileJob, error) {
			var out ProfileJob
			err := client.Call(ctx, "import-profile", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_update_profile", Description: "Start an asynchronous update of a remote subscription. Poll netflow_profile_job_status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProfileArgs) (*mcp.CallToolResult, ProfileJob, error) {
			var out ProfileJob
			err := client.Call(ctx, "update-profile", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_profile_job_status", Description: "Read a subscription import or update job. Completed jobs are retained for up to ten minutes, subject to capacity.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProfileJobArgs) (*mcp.CallToolResult, ProfileJob, error) {
			var out ProfileJob
			err := client.Call(ctx, "profile-job-status", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_delete_profile", Description: "Delete an inactive profile and its profile-scoped rewrites. The active profile cannot be deleted.", Annotations: &mcp.ToolAnnotations{DestructiveHint: func() *bool { b := true; return &b }()}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProfileArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "delete-profile", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_providers", Description: "List a bounded first page of proxy and rule providers without URLs or paths; use netflow_provider_page to continue.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ProviderList, error) {
			var out ProviderList
			err := client.Call(ctx, "providers", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_provider_page", Description: "Page proxy or rule provider summaries. Use next_offset; provider lists can change after reload.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ProviderPageArgs) (*mcp.CallToolResult, ProviderPageResult, error) {
			var out ProviderPageResult
			err := client.Call(ctx, "provider-page", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_update_provider", Description: "Start an asynchronous update for a named proxy or rule provider in the active profile. Poll netflow_provider_job_status using the returned job_id. A profile change before the job starts causes it to fail."},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProviderUpdateArgs) (*mcp.CallToolResult, ProviderJob, error) {
			var out ProviderJob
			err := client.Call(ctx, "update-provider", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_provider_job_status", Description: "Read an asynchronous provider update job. Completed jobs are kept for up to ten minutes, subject to capacity.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ProviderJobArgs) (*mcp.CallToolResult, ProviderJob, error) {
			var out ProviderJob
			err := client.Call(ctx, "provider-job-status", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_rules", Description: "Read active kernel rules in evaluation order. Pages may be shorter than requested; use next_offset until total. The list can change on reload.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in RulesArgs) (*mcp.CallToolResult, RulesResult, error) {
		var out RulesResult
		err := client.Call(ctx, "rules", in, &out)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_select_proxy", Description: "Select a member of a selectable proxy group; affects subsequent connections and persists the choice when possible."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in SelectArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "select", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_set_mode", Description: "Set routing mode to rule, global, or direct; changes network routing."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ModeArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "mode", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_use_profile", Description: "Activate an existing subscription profile and reload the core; may interrupt connections."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ProfileArgs) (*mcp.CallToolResult, ActionResult, error) {
			var out ActionResult
			err := client.Call(ctx, "use-profile", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_close_connection", Description: "Close one identified active connection. Returns closed=false if it already ended.", Annotations: &mcp.ToolAnnotations{DestructiveHint: func() *bool { b := true; return &b }()}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ConnectionArgs) (*mcp.CallToolResult, CloseResult, error) {
			var out CloseResult
			err := client.Call(ctx, "close-connection", in, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_migration_preview", Description: "Inspect a Clash Verge configuration directory or backup ZIP without modifying it. Reports unsupported extensions.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *mcp.CallToolRequest, in MigrationPath) (*mcp.CallToolResult, migration.Preview, error) {
			if !filepath.IsAbs(in.Path) {
				return nil, migration.Preview{}, errors.New("source path must be absolute")
			}
			source, err := migration.ReadVerge(in.Path)
			if err != nil {
				return nil, migration.Preview{}, err
			}
			return nil, source.Preview(), nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_migration_import", Description: "Import Clash Verge profiles into this NetFlow configuration. Close NetFlow first; existing profiles are preserved and unexecuted extensions are archived."},
		func(_ context.Context, _ *mcp.CallToolRequest, in MigrationPath) (*mcp.CallToolResult, migration.ImportResult, error) {
			if !filepath.IsAbs(in.Path) || !filepath.IsAbs(client.Dir) {
				return nil, migration.ImportResult{}, errors.New("source and config paths must be absolute")
			}
			source, err := migration.ReadVerge(in.Path)
			if err != nil {
				return nil, migration.ImportResult{}, err
			}
			if err = source.ValidateTarget(client.Dir); err != nil {
				return nil, migration.ImportResult{}, err
			}
			lock, err := appdir.Acquire(client.Dir)
			if err != nil {
				return nil, migration.ImportResult{}, err
			}
			defer lock.Close()
			result, err := source.ImportVerge(client.Dir)
			return nil, result, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_migration_export", Description: "Export a new Clash Verge-compatible backup ZIP without overwriting a file. Close NetFlow first; output may contain credentials and preserved scripts."},
		func(_ context.Context, _ *mcp.CallToolRequest, in MigrationPath) (*mcp.CallToolResult, migration.ExportResult, error) {
			if !filepath.IsAbs(in.Path) || !filepath.IsAbs(client.Dir) {
				return nil, migration.ExportResult{}, errors.New("destination and config paths must be absolute")
			}
			lock, err := appdir.Acquire(client.Dir)
			if err != nil {
				return nil, migration.ExportResult{}, err
			}
			defer lock.Close()
			result, err := migration.ExportVerge(client.Dir, in.Path)
			return nil, result, err
		})
	return s
}

func ServeMCP(ctx context.Context, client Client) error {
	return NewMCP(client).Run(ctx, &mcp.StdioTransport{MaxLineLength: 1 << 20})
}
