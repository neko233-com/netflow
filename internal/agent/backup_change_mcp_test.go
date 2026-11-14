package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
)

func TestBackupOnChangeMCPForwardsOptIn(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, args json.RawMessage) (any, error) {
		var in BackupOnChangeArgs
		if method != "backup-on-change" || json.Unmarshal(args, &in) != nil || !in.Enabled {
			return nil, errors.New("invalid opt-in request")
		}
		return BackupSchedule{Enabled: true, OnChange: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := NewMCP(Client{Dir: dir}).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "backup-test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_backup_on_change", Arguments: map[string]any{"enabled": true}})
	if err != nil || result.IsError {
		t.Fatalf("MCP opt-in failed: %+v %v", result, err)
	}
}
