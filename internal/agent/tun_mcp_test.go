package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPRequestsTUN(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, args json.RawMessage) (any, error) {
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
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_set_tun", Arguments: map[string]any{"enabled": false}})
	if err != nil || result.IsError {
		t.Fatalf("TUN tool failed: %v %+v", err, result)
	}
}
