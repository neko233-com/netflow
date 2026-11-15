package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCancelApplyMCP(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		if method != "cancel-apply" {
			return nil, errors.New("unexpected method")
		}
		return CancelApplyResult{Accepted: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx := context.Background()
	server := NewMCP(Client{Dir: dir})
	client := mcp.NewClient(&mcp.Implementation{Name: "cancel-test", Version: "1"}, nil)
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
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_cancel_apply", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("cancel tool: %+v %v", result, err)
	}
	data, err := json.Marshal(result.StructuredContent)
	var value CancelApplyResult
	if err != nil || json.Unmarshal(data, &value) != nil || !value.Accepted {
		t.Fatalf("cancel response: %s %v", data, err)
	}
}
