package agent

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Empty struct{}

// NewMCP exposes a two-step preview/apply interface over the authenticated
// local bridge. No subscription URLs, core secrets, or token are returned.
func NewMCP(client Client) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netflow", Version: "0.2.4"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "netflow_status", Description: "List the running core, profiles, active connections and agent-managed rewrite state. Subscription URLs are omitted.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, Status, error) {
			var out Status
			err := client.Call(ctx, "status", nil, &out)
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
	return s
}

func ServeMCP(ctx context.Context, client Client) error {
	return NewMCP(client).Run(ctx, &mcp.StdioTransport{MaxLineLength: 1 << 20})
}
