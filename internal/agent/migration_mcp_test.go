package agent

import (
	"context"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/neko233-com/netflow/internal/profile"
)

func TestRealVergeImportThroughMCP(t *testing.T) {
	source := os.Getenv("NETFLOW_TEST_VERGE_SOURCE")
	if source == "" {
		t.Skip("real Verge source not configured")
	}
	target := t.TempDir()
	ctx := context.Background()
	server := NewMCP(Client{Dir: target})
	client := mcp.NewClient(&mcp.Implementation{Name: "migration-test", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for _, name := range []string{"netflow_migration_preview", "netflow_migration_import"} {
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"path": source}})
		if err != nil || result.IsError {
			t.Fatalf("%s failed: %v", name, err)
		}
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || len(catalog.Items) == 0 {
		t.Fatal("MCP import produced no profiles")
	}
}
