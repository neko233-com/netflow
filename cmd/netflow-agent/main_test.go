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

func TestOfflineBackupCLIRespectsLockAndRestoresNewDirectory(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config.yaml"), []byte("rules: [MATCH,DIRECT]"), 0600); err != nil {
		t.Fatal(err)
	}
	archive, target := filepath.Join(base, "backup.zip"), filepath.Join(base, "restored")
	var output bytes.Buffer
	lock, err := appdir.Acquire(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", source, "backup-export", archive}, bytes.NewReader(nil), &output); err == nil {
		t.Fatal("backup accepted while app directory was locked")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", source, "backup-export", archive}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"--config-dir", target, "backup-restore", archive}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "config.yaml"))
	if err != nil || string(data) != "rules: [MATCH,DIRECT]" {
		t.Fatalf("restored config: %v", err)
	}
}

func TestImportProfileCLIReadsCredentialsFromStdin(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		var input agent.ProfileImportArgs
		if method != "import-profile" || json.Unmarshal(raw, &input) != nil || input.URL != "https://example.invalid/?token=synthetic-secret" {
			return nil, errors.New("unexpected request")
		}
		return agent.ProfileJob{JobID: "job", State: "pending"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	err = run([]string{"--config-dir", dir, "import-profile"}, strings.NewReader(`{"url":"https://example.invalid/?token=synthetic-secret"}`), &output)
	if err != nil || strings.Contains(output.String(), "synthetic-secret") || !strings.Contains(output.String(), `"job_id":"job"`) {
		t.Fatalf("unexpected CLI result: %s %v", output.String(), err)
	}
	if err := run([]string{"--config-dir", dir, "import-profile", "unexpected"}, strings.NewReader(`{}`), &output); err == nil {
		t.Fatal("CLI accepted URL argument")
	}
}

func TestConnectionsCLIPage(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		var in agent.ConnectionsArgs
		if method != "connections" || json.Unmarshal(raw, &in) != nil || in.Offset != 2 || in.Limit != 3 {
			return nil, errors.New("unexpected connection page request")
		}
		return agent.ConnectionsResult{Total: 2, Offset: 2, NextOffset: 2}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var out bytes.Buffer
	if err := run([]string{"--config-dir", dir, "connections", "2", "3"}, strings.NewReader(""), &out); err != nil || !strings.Contains(out.String(), `"next_offset":2`) {
		t.Fatalf("connection page: %s %v", out.String(), err)
	}
	for _, args := range [][]string{{"-1"}, {"0", "501"}, {"invalid"}, {"0", "1", "extra"}} {
		out.Reset()
		if err := run(append([]string{"--config-dir", dir, "connections"}, args...), strings.NewReader(""), &out); err == nil {
			t.Fatalf("accepted invalid connection arguments: %v", args)
		}
	}
}

func TestKernelOptionCLI(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		if method == "kernel-options" {
			return agent.KernelOptionsResult{}, nil
		}
		var in agent.KernelOptionArgs
		if method != "kernel-option" || json.Unmarshal(raw, &in) != nil || in.Name != "ipv6" || in.BoolValue == nil || !*in.BoolValue {
			return nil, errors.New("unexpected request")
		}
		return agent.KernelOptionsResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	if err := run([]string{"--config-dir", dir, "kernel-options"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "kernel-option", "ipv6", "true"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"ipv6", "yes"}, {"unknown", "inherit"}, {"http-port", "many"}} {
		if _, err := parseKernelOption(args[0], args[1]); err == nil {
			t.Fatalf("invalid option accepted: %v", args)
		}
	}
	if value, err := parseKernelOption("tun-stack", "inherit"); err != nil || !value.Inherit {
		t.Fatal("inheritance was not parsed")
	}
}

func TestRollbackCLIUsesPreview(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		if method == "rewrite-history" {
			return agent.RewriteHistory{}, nil
		}
		if method == "preview-rules" {
			var in agent.PreviewRulesArgs
			if json.Unmarshal(raw, &in) != nil || in.ProposalID != "proposal" || in.Stage != "after" || in.Offset != 2 || in.Limit != 3 {
				return nil, errors.New("incorrect preview page request")
			}
			return agent.PreviewRulesResult{Total: 3, Offset: 2, NextOffset: 3, Rules: []string{"MATCH,DIRECT"}}, nil
		}
		if method == "cancel-preview" {
			return agent.ActionResult{OK: true}, nil
		}
		if method == "clear-rewrite-history" {
			return agent.ClearRewriteHistoryResult{Revision: 2}, nil
		}
		var in agent.RollbackArgs
		if method != "rollback-preview" || json.Unmarshal(raw, &in) != nil || in.Revision == nil || *in.Revision != 0 || in.Scope != "global" {
			return nil, errors.New("unexpected rollback request")
		}
		return agent.Preview{ProposalID: "proposal"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	if err := run([]string{"--config-dir", dir, "rewrite-history"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "clear-rewrite-history"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "preview-rules", "proposal", "after", "2", "3"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "cancel-preview", "proposal"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "preview-rules", "proposal", "after", "-1"}, strings.NewReader(""), &output); err == nil {
		t.Fatal("negative offset accepted")
	}
	if err := run([]string{"--config-dir", dir, "rollback-preview"}, strings.NewReader(`{"revision":0,"scope":"global"}`), &output); err != nil || !strings.Contains(output.String(), "proposal") {
		t.Fatalf("rollback preview failed: %v", err)
	}
	if err := run([]string{"--config-dir", dir, "rollback-preview"}, strings.NewReader(`{"revision":0,"scope":"global","unknown":1}`), &output); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestProfileSettingsCLIReadsPatchFromStdin(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		if method == "profile-url-set" {
			var in agent.ProfileURLArgs
			if json.Unmarshal(raw, &in) != nil || in.ProfileID != "profile" || in.URL != "https://example.invalid/?token=synthetic-secret" {
				return nil, errors.New("unexpected URL request")
			}
			return agent.ProfileJob{JobID: "job", State: "pending"}, nil
		}
		if method == "profile-settings" {
			return agent.ProfileSettings{ProfileID: "profile", Name: "test"}, nil
		}
		var in agent.ProfileSettingsPatch
		if method != "profile-settings-set" || json.Unmarshal(raw, &in) != nil || in.ProfileID != "profile" || in.Timeout == nil || *in.Timeout != 25 {
			return nil, errors.New("unexpected profile settings request")
		}
		return agent.ProfileSettings{ProfileID: in.ProfileID, Name: "test", Timeout: *in.Timeout}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	if err := run([]string{"--config-dir", dir, "profile-settings", "profile"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "profile-settings-set"}, strings.NewReader(`{"profile_id":"profile","timeout_seconds":25}`), &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config-dir", dir, "profile-settings-set"}, strings.NewReader(`{"profile_id":"profile","unknown":1}`), &output); err == nil {
		t.Fatal("unknown patch field accepted")
	}
	if err := run([]string{"--config-dir", dir, "profile-url-set"}, strings.NewReader(`{"profile_id":"profile","url":"https://example.invalid/?token=synthetic-secret"}`), &output); err != nil || strings.Contains(output.String(), "synthetic-secret") {
		t.Fatalf("URL request failed or leaked: %v", err)
	}
}

func TestWebDAVCLIReadsCredentialsFromStdinWithoutEcho(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		var input agent.WebDAVUploadArgs
		if method != "webdav-upload" || json.Unmarshal(raw, &input) != nil || input.Password != "synthetic-secret" || input.URL != "https://example.invalid/?token=synthetic-token" {
			return nil, errors.New("unexpected request")
		}
		return agent.BackupJob{JobID: "job", State: "pending"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	input, _ := json.Marshal(agent.WebDAVUploadArgs{Archive: filepath.Join(dir, "backup.zip"), URL: "https://example.invalid/?token=synthetic-token", Password: "synthetic-secret"})
	var output bytes.Buffer
	err = run([]string{"--config-dir", dir, "webdav-upload"}, bytes.NewReader(input), &output)
	if err != nil || strings.Contains(output.String(), "synthetic-") || !strings.Contains(output.String(), `"job_id":"job"`) {
		t.Fatalf("unexpected CLI result: %s %v", output.String(), err)
	}
	err = run([]string{"--config-dir", dir, "webdav-upload"}, strings.NewReader(`{"synthetic-secret":"x"}`), &output)
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("malformed input was accepted or exposed")
	}
}

func TestWebDAVSaveCLIUsesStdinAndDoesNotEchoSecrets(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		var input agent.WebDAVConfigArgs
		if method != "webdav-save" || json.Unmarshal(raw, &input) != nil || input.Password != "synthetic-secret" {
			return nil, errors.New("unexpected request")
		}
		return agent.ActionResult{OK: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	err = run([]string{"--config-dir", dir, "webdav-save"}, strings.NewReader(`{"url":"https://example.invalid/?token=synthetic-token","password":"synthetic-secret"}`), &output)
	if err != nil || strings.Contains(output.String(), "synthetic-") || !strings.Contains(output.String(), `"ok":true`) {
		t.Fatalf("unexpected CLI result: %s %v", output.String(), err)
	}
}

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

func TestTUNAutoStartCLI(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		switch method {
		case "tun-autostart":
			return agent.TunAutoStartResult{AppliesTo: "gui"}, nil
		case "tun-autostart-set":
			var in agent.TunArgs
			if json.Unmarshal(raw, &in) != nil || in.Enabled == nil || !*in.Enabled {
				return nil, errors.New("invalid startup request")
			}
			return agent.TunAutoStartResult{Enabled: true, AppliesTo: "gui"}, nil
		default:
			return nil, errors.New("unexpected method")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	for _, args := range [][]string{{"tun-autostart"}, {"tun-autostart", "on"}} {
		var output bytes.Buffer
		if err := run(append([]string{"--config-dir", dir}, args...), strings.NewReader(""), &output); err != nil || !json.Valid(output.Bytes()) {
			t.Fatalf("%v: %s %v", args, output.String(), err)
		}
	}
	if err := run([]string{"--config-dir", dir, "tun-autostart", "invalid"}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("invalid argument accepted")
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
