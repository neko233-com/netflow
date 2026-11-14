package agent

import (
	"context"
	"errors"
	"path/filepath"

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
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_status", Description: "List the running core, profiles, active connections and agent-managed rewrite state. Subscription URLs are omitted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Status, error) {
			var out Status
			err := client.Call(ctx, "status", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_diagnostics", Description: "Return an allowlisted diagnostics summary without subscription URLs, file paths, error text, tokens, or connection metadata.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Diagnostics, error) {
			var out Diagnostics
			err := client.Call(ctx, "diagnostics", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_kernel_options", Description: "Read explicit kernel overrides; omitted settings inherit the active subscription.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
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
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_apply_rewrite", Description: "Apply an unexpired preview proposal if its configuration and revision are unchanged. This changes network routing; an explicitly requested connection close may interrupt that connection.", Annotations: &mcp.ToolAnnotations{}},
		func(ctx context.Context, _ *mcp.CallToolRequest, args ApplyArgs) (*mcp.CallToolResult, ApplyResult, error) {
			var out ApplyResult
			err := client.Call(ctx, "apply", args, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_proxy_groups", Description: "List live proxy groups, selected nodes, and resolved members without subscription credentials.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, GroupsResult, error) {
			var out GroupsResult
			err := client.Call(ctx, "groups", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_profiles", Description: "List profile IDs, user-controlled names and the active profile without a subscription URL field.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ProfileList, error) {
			var out ProfileList
			err := client.Call(ctx, "profiles", nil, &out)
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
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_providers", Description: "List active proxy and rule providers without their URLs or local paths.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, ProviderList, error) {
			var out ProviderList
			err := client.Call(ctx, "providers", nil, &out)
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
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_rules", Description: "Read a page of active kernel rules in evaluation order.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, in RulesArgs) (*mcp.CallToolResult, RulesResult, error) {
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
