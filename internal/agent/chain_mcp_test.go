package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestChainMCPToolsUseTypedBridgeRequests(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, args json.RawMessage) (any, error) {
		switch method {
		case "chain-preview":
			var in ChainPreviewArgs
			if json.Unmarshal(args, &in) != nil || in.Target != "Target" || len(in.Hops) != 2 || in.Hops[1].Provider != "source" {
				return nil, errors.New("bad chain preview")
			}
			return ChainPreview{ProposalID: "p"}, nil
		case "chain-apply":
			var in ApplyArgs
			if json.Unmarshal(args, &in) != nil || in.ProposalID != "p" {
				return nil, errors.New("bad proposal")
			}
			return ChainStatus{Configured: true, Active: true}, nil
		case "chain-status":
			return ChainStatus{Configured: true, Active: true}, nil
		case "chain-disconnect", "chain-cancel-preview":
			return ActionResult{OK: true}, nil
		default:
			return nil, errors.New("unknown method")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx := context.Background()
	server := NewMCP(Client{Dir: dir})
	client := mcp.NewClient(&mcp.Implementation{Name: "chain-test", Version: "1"}, nil)
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
	calls := []*mcp.CallToolParams{
		{Name: "netflow_preview_chain", Arguments: map[string]any{"target": "Target", "hops": []map[string]any{{"name": "entry", "group": "Target"}, {"name": "exit", "provider": "source", "group": "Target"}}}},
		{Name: "netflow_apply_chain", Arguments: map[string]any{"proposal_id": "p"}},
		{Name: "netflow_chain_status", Arguments: map[string]any{}},
		{Name: "netflow_cancel_chain_preview", Arguments: map[string]any{"proposal_id": "p"}},
		{Name: "netflow_disconnect_chain", Arguments: map[string]any{}},
	}
	for _, call := range calls {
		result, err := cs.CallTool(ctx, call)
		if err != nil || result.IsError {
			t.Fatalf("%s: %+v %v", call.Name, result, err)
		}
	}
}
