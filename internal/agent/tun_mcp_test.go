package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/neko233-com/netflow"
)

func TestMCPRequestsTUN(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, args json.RawMessage) (any, error) {
		if method == "diagnostics" {
			return Diagnostics{SchemaVersion: 1, ProfileCount: 2}, nil
		}
		if method == "update-geo" {
			return GeoResult{Accepted: true, Pending: true}, nil
		}
		var in TunArgs
		if method != "tun" || json.Unmarshal(args, &in) != nil || in.Enabled == nil || *in.Enabled {
			t.Error("incorrect TUN request")
		}
		return TunResult{Accepted: true, Pending: false, TUN: false}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx := context.Background()
	server := NewMCP(Client{Dir: dir})
	client := mcp.NewClient(&mcp.Implementation{Name: "tun-test", Version: "1"}, nil)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if got := cs.InitializeResult().ServerInfo.Version; got != netflow.Version() {
		t.Fatalf("MCP version %q does not match the application version %q", got, netflow.Version())
	}
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_set_tun", Arguments: map[string]any{"enabled": false}})
	if err != nil || result.IsError {
		t.Fatalf("TUN tool failed: %v %+v", err, result)
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_diagnostics", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("diagnostics tool failed: %v %+v", err, result)
	}
	data, err := json.Marshal(result.StructuredContent)
	var diagnostics Diagnostics
	if err != nil || json.Unmarshal(data, &diagnostics) != nil || diagnostics.SchemaVersion != 1 || diagnostics.ProfileCount != 2 {
		t.Fatalf("unexpected MCP diagnostics: %s %v", data, err)
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_update_geodata", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("GeoData tool failed: %v %+v", err, result)
	}
	data, err = json.Marshal(result.StructuredContent)
	var geo GeoResult
	if err != nil || json.Unmarshal(data, &geo) != nil || !geo.Accepted || !geo.Pending {
		t.Fatalf("unexpected GeoData result: %s %v", data, err)
	}
}
