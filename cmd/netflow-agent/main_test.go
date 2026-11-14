package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/profile"
)

func TestRealVergeImportThroughCLI(t *testing.T) {
	source := os.Getenv("NETFLOW_TEST_VERGE_SOURCE")
	if source == "" {
		t.Skip("real Verge source not configured")
	}
	target := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"--config-dir", target, "migrate-preview", source}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		Profiles []struct {
			ID string `json:"id"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || len(preview.Profiles) == 0 {
		t.Fatal("invalid CLI migration preview")
	}
	out.Reset()
	lock, err := appdir.Acquire(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"--config-dir", target, "migrate-import", source}, bytes.NewReader(nil), &out); err == nil {
		t.Fatal("import accepted while target was locked")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"--config-dir", target, "migrate-import", source}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Imported int `json:"imported"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Imported != len(preview.Profiles) {
		t.Fatal("CLI import count mismatch")
	}
	cat, err := profile.NewStore(target).Load()
	if err != nil || len(cat.Items) != result.Imported {
		t.Fatal("CLI import catalog mismatch")
	}
	for _, item := range cat.Items {
		if _, err = os.Stat(filepath.Join(target, item.File)); err != nil {
			t.Fatal("CLI import file missing")
		}
	}
}

func TestVersionMatchesPackagingManifestWithoutConfig(t *testing.T) {
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "mygo.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || manifest.Version == "" {
		t.Fatalf("invalid packaging version: %v", err)
	}
	t.Setenv("NETFLOW_CONFIG_DIR", "relative-path-is-invalid")
	var output bytes.Buffer
	if err := run([]string{"version"}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Version != manifest.Version {
		t.Fatalf("version differs from packaging manifest: %s %v", output.String(), err)
	}
}

func TestPreviewRejectsTrailingAndOversizedInputBeforeBridge(t *testing.T) {
	for _, input := range []string{`{"scope":"global","operation":"clear"} {}`, strings.Repeat(" ", (1<<20)+1)} {
		var out bytes.Buffer
		err := run([]string{"--config-dir", t.TempDir(), "preview"}, strings.NewReader(input), &out)
		if err == nil || strings.Contains(err.Error(), "bridge") {
			t.Fatalf("invalid preview input accepted: %v", err)
		}
	}
}

func TestTUNCommandUsesBridge(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, args json.RawMessage) (any, error) {
		var in agent.TunArgs
		if method != "tun" || json.Unmarshal(args, &in) != nil || in.Enabled == nil || !*in.Enabled {
			t.Error("incorrect TUN request")
		}
		return agent.TunResult{Accepted: true, Pending: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var out bytes.Buffer
	if err = run([]string{"--config-dir", dir, "tun", "on"}, bytes.NewReader(nil), &out); err != nil {
		t.Fatal(err)
	}
	var result agent.TunResult
	if json.Unmarshal(out.Bytes(), &result) != nil || !result.Accepted || !result.Pending {
		t.Fatalf("unexpected response %s", out.String())
	}
	if err = run([]string{"--config-dir", dir, "tun", "bad"}, bytes.NewReader(nil), &out); err == nil {
		t.Fatal("invalid TUN argument accepted")
	}
}

func TestDiagnosticsCommandUsesBridge(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		if method != "diagnostics" {
			t.Errorf("unexpected bridge method: %s", method)
		}
		return agent.Diagnostics{SchemaVersion: 1, ProfileCount: 2}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	if err := run([]string{"--config-dir", dir, "diagnostics"}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	var result agent.Diagnostics
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.SchemaVersion != 1 || result.ProfileCount != 2 {
		t.Fatalf("unexpected diagnostics: %s %v", output.String(), err)
	}
}

func TestGeoUpdateCommandUsesBridge(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		if method != "update-geo" {
			t.Errorf("unexpected bridge method: %s", method)
		}
		return agent.GeoResult{Accepted: true, Pending: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	if err := run([]string{"--config-dir", dir, "update-geo"}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	var result agent.GeoResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Accepted || !result.Pending {
		t.Fatalf("unexpected response: %s %v", output.String(), err)
	}
}

func TestProviderCommandsUseBridge(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		switch method {
		case "providers":
			return agent.ProviderList{Proxy: []agent.ProviderInfo{{Name: "nodes"}}}, nil
		case "update-provider":
			var input agent.ProviderUpdateArgs
			if json.Unmarshal(raw, &input) != nil || input.Kind != "rule" || input.Name != "sites" {
				t.Error("wrong provider arguments")
			}
			return agent.ProviderJob{JobID: "0123456789abcdef0123456789abcdef", State: "pending"}, nil
		case "provider-job-status":
			return agent.ProviderJob{State: "succeeded"}, nil
		default:
			return nil, errors.New("unexpected method")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	for _, args := range [][]string{{"providers"}, {"update-provider", "rule", "sites"}, {"provider-job-status", "0123456789abcdef0123456789abcdef"}} {
		var out bytes.Buffer
		if err := run(append([]string{"--config-dir", dir}, args...), bytes.NewReader(nil), &out); err != nil || !json.Valid(out.Bytes()) {
			t.Fatalf("%v: %s %v", args, out.String(), err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"--config-dir", dir, "update-provider", "invalid", "name"}, bytes.NewReader(nil), &out); err == nil {
		t.Fatal("invalid kind accepted")
	}
}
