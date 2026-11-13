package agent

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/migration"
)

type Empty struct{}

// NewMCP exposes a two-step preview/apply interface over the authenticated
// local bridge. No subscription URLs, core secrets, or token are returned.
func NewMCP(client Client) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netflow", Version: "0.2.7"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_status", Description: "List the running core, profiles, active connections and agent-managed rewrite state. Subscription URLs are omitted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Status, error) {
			var out Status
			err := client.Call(ctx, "status", nil, &out)
			return nil, out, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_set_tun", Description: "Request TUN on or off; enabling may show a Windows administrator consent prompt. If pending, poll netflow_status for tun_pending and tun_error."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TunArgs) (*mcp.CallToolResult, TunResult, error) {
			var out TunResult
			err := client.Call(ctx, "tun", in, &out)
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
