package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDelayMCPUsesTypedRequests(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		switch method {
		case "delay-test":
			var in DelayArgs
			if json.Unmarshal(raw, &in) != nil || in.Group != "group" || in.Node != "node" || in.TimeoutMS != 2500 {
				return nil, errors.New("bad request")
			}
			return DelayJob{JobID: "job", State: "pending"}, nil
		case "delay-job-status":
			var in DelayJobArgs
			if json.Unmarshal(raw, &in) != nil || in.JobID != "job" {
				return nil, errors.New("bad job")
			}
			return DelayJob{JobID: "job", State: "succeeded", DelayMS: 42}, nil
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
	client := mcp.NewClient(&mcp.Implementation{Name: "delay-test", Version: "1"}, nil)
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
	for _, call := range []*mcp.CallToolParams{
		{Name: "netflow_test_proxy_delay", Arguments: map[string]any{"group": "group", "node": "node", "timeout_ms": 2500}},
		{Name: "netflow_delay_job_status", Arguments: map[string]any{"job_id": "job"}},
	} {
		out, err := cs.CallTool(ctx, call)
		if err != nil || out.IsError {
			t.Fatalf("%s: %+v %v", call.Name, out, err)
		}
	}
}
