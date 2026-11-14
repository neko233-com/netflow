package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestVergeScriptMCPPreviewAndPaging(t *testing.T) {
	dir := t.TempDir()
	bridge, err := Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		switch method {
		case "verge-script-preview":
			var in VergeScriptPreviewArgs
			if json.Unmarshal(raw, &in) != nil || in.ProfileID != "sub" || !in.Global || !in.Profile {
				return nil, errors.New("bad preview")
			}
			return VergeScriptPreview{PreviewID: "p", Warnings: []string{"read only"}}, nil
		case "verge-script-preview-rules":
			var in PreviewRulesArgs
			if json.Unmarshal(raw, &in) != nil || in.ProposalID != "p" || in.Stage != "after" {
				return nil, errors.New("bad page")
			}
			return PreviewRulesResult{Rules: []string{"MATCH,DIRECT"}}, nil
		case "verge-script-preview-config":
			var in VergeScriptConfigArgs
			if json.Unmarshal(raw, &in) != nil || in.PreviewID != "p" || in.Stage != "after" {
				return nil, errors.New("bad config page")
			}
			return VergeScriptConfigPage{Text: "private fixture"}, nil
		case "verge-script-preview-cancel":
			return ActionResult{OK: true}, nil
		default:
			return nil, errors.New("unexpected method")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	ctx := context.Background()
	server := NewMCP(Client{Dir: dir})
	client := mcp.NewClient(&mcp.Implementation{Name: "verge-test", Version: "1"}, nil)
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
		{Name: "netflow_preview_verge_script", Arguments: map[string]any{"profile_id": "sub", "global": true, "profile": true}},
		{Name: "netflow_verge_script_preview_rules", Arguments: map[string]any{"proposal_id": "p", "stage": "after"}},
		{Name: "netflow_verge_script_preview_config", Arguments: map[string]any{"preview_id": "p", "stage": "after"}},
		{Name: "netflow_cancel_verge_script_preview", Arguments: map[string]any{"proposal_id": "p"}},
	} {
		result, err := cs.CallTool(ctx, call)
		if err != nil || result.IsError {
			t.Fatalf("%s: %v %+v", call.Name, err, result)
		}
	}
}
