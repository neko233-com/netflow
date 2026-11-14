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
		if method == "profile-url-set" {
			var in ProfileURLArgs
			if json.Unmarshal(args, &in) != nil || in.ProfileID != "profile" || in.URL != "https://example.invalid/?token=synthetic-secret" {
				t.Error("incorrect profile URL request")
			}
			return ProfileJob{JobID: "job", State: "pending"}, nil
		}
		if method == "profile-settings" {
			return ProfileSettings{ProfileID: "profile", Name: "test"}, nil
		}
		if method == "profile-settings-set" {
			var in ProfileSettingsPatch
			if json.Unmarshal(args, &in) != nil || in.ProfileID != "profile" || in.AutoUpdate == nil || !*in.AutoUpdate {
				t.Error("incorrect profile settings request")
			}
			return ProfileSettings{ProfileID: "profile", Name: "test", AutoUpdate: true}, nil
		}
		if method == "kernel-options" {
			return KernelOptionsResult{}, nil
		}
		if method == "kernel-option" {
			var in KernelOptionArgs
			if json.Unmarshal(args, &in) != nil || in.Name != "ipv6" || in.BoolValue == nil || !*in.BoolValue {
				t.Error("incorrect kernel option request")
			}
			return KernelOptionsResult{}, nil
		}
		if method == "diagnostics" {
			return Diagnostics{SchemaVersion: 1, ProfileCount: 2}, nil
		}
		if method == "update-geo" {
			return GeoResult{Accepted: true, Pending: true}, nil
		}
		if method == "providers" {
			return ProviderList{Proxy: []ProviderInfo{{Name: "nodes", Vehicle: "HTTP", Count: 2}}, Rule: []ProviderInfo{}}, nil
		}
		if method == "update-provider" {
			var in ProviderUpdateArgs
			if json.Unmarshal(args, &in) != nil || in.Kind != "proxy" || in.Name != "nodes" {
				t.Error("incorrect provider request")
			}
			return ProviderJob{JobID: "0123456789abcdef0123456789abcdef", State: "pending"}, nil
		}
		if method == "provider-job-status" {
			return ProviderJob{JobID: "0123456789abcdef0123456789abcdef", State: "succeeded"}, nil
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
	for _, call := range []*mcp.CallToolParams{
		{Name: "netflow_kernel_options", Arguments: map[string]any{}},
		{Name: "netflow_set_kernel_option", Arguments: map[string]any{"name": "ipv6", "bool_value": true}},
		{Name: "netflow_profile_settings", Arguments: map[string]any{"profile_id": "profile"}},
		{Name: "netflow_update_profile_settings", Arguments: map[string]any{"profile_id": "profile", "auto_update": true}},
		{Name: "netflow_replace_profile_url", Arguments: map[string]any{"profile_id": "profile", "url": "https://example.invalid/?token=synthetic-secret"}},
	} {
		result, err := cs.CallTool(ctx, call)
		if err != nil || result.IsError {
			t.Fatalf("kernel option tool failed: %v %+v", err, result)
		}
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
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_providers", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("provider list failed: %v %+v", err, result)
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_update_provider", Arguments: map[string]any{"kind": "proxy", "name": "nodes"}})
	if err != nil || result.IsError {
		t.Fatalf("provider update failed: %v %+v", err, result)
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "netflow_provider_job_status", Arguments: map[string]any{"job_id": "0123456789abcdef0123456789abcdef"}})
	if err != nil || result.IsError {
		t.Fatalf("provider job failed: %v %+v", err, result)
	}
}
