package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIVergeScriptApplyCancellationAndRollback(t *testing.T) {
	for _, scenario := range []string{"cancel", "context-cancel", "agent-cancel", "headless-agent-cancel", "headless-quit", "success", "external-catalog", "rollback-fails", "sensitive-error", "update-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("CI", "1")
			source := t.TempDir()
			if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
				t.Fatal(err)
			}
			base := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t))
			files := map[string]string{
				"profiles.yaml":       "current: p1\nitems:\n  - {uid: p1, type: local, name: Test, file: p1.yaml, option: {script: s1}}\n  - {uid: s1, type: script, file: profile.js}\n",
				"profiles/p1.yaml":    base,
				"profiles/profile.js": `function main(c){c.rules.unshift("DOMAIN,script.test,DIRECT");return c}`,
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			parsed, err := migration.ReadVerge(source)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if _, err = parsed.ImportVerge(dir); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			underlying := a.core
			defer underlying.Stop()
			d := newSerialDispatcher()
			a.dispatch = d.call
			a.headless = scenario == "headless-agent-cancel" || scenario == "headless-quit"
			defer d.close()
			previewArgs, _ := json.Marshal(agent.VergeScriptPreviewArgs{Profile: true})
			previewCall := func(method string, args json.RawMessage) agent.VergeScriptPreview {
				t.Helper()
				value, err := a.dispatchAgent(context.Background(), method, args)
				if err != nil {
					t.Fatal(err)
				}
				return value.(agent.VergeScriptPreview)
			}
			preview := previewCall("verge-script-preview", previewArgs)
			var server *httptest.Server
			if scenario == "update-cancel" {
				input, _ := json.Marshal(agent.ApplyArgs{ProposalID: preview.PreviewID})
				if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", input); err != nil {
					t.Fatal(err)
				}
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(strings.Replace(base, "MATCH,DIRECT", "DOMAIN,updated.test,DIRECT", 1)))
				}))
				defer server.Close()
				catalog, snapshot, err := a.profiles.LoadForUpdate()
				if err != nil {
					t.Fatal(err)
				}
				catalog.Items[0].Type = "remote"
				catalog.Items[0].URL = server.URL
				if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
					t.Fatal(err)
				}
				args, _ := json.Marshal(agent.VergeScriptUpdateArgs{ProfileID: catalog.Items[0].UID})
				preview = previewCall("verge-script-update-preview", args)
			}
			catalogBefore, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if err != nil {
				t.Fatal(err)
			}
			configBefore, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			engine := &controlledChainReload{coreEngine: underlying, entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{}), failRestore: scenario == "rollback-fails"}
			if scenario == "sensitive-error" {
				engine.failAfterRelease = errors.New("https://user:synthetic-secret@example.invalid/subscription")
				engine.failRestore = true
				engine.restoreFailure = errors.New("synthetic-secret in rollback")
			}
			a.core = engine
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input, _ := json.Marshal(agent.ApplyArgs{ProposalID: preview.PreviewID})
			result := make(chan error, 1)
			go func() { _, err := a.dispatchAgent(ctx, "verge-script-apply", input); result <- err }()
			select {
			case <-engine.entered:
			case err := <-result:
				t.Fatalf("apply ended before reload: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("reload did not start")
			}
			pulse := make(chan struct{})
			go d.call(func() { close(pulse) })
			select {
			case <-pulse:
			case <-time.After(time.Second):
				t.Fatal("event loop blocked")
			}
			var op *guiConfigOperation
			d.call(func() { op = a.guiOperation })
			if op == nil {
				t.Fatal("missing GUI transaction")
			}
			if scenario == "external-catalog" {
				if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte("external edit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "success", "sensitive-error":
				close(engine.release)
			case "context-cancel":
				cancel()
			case "agent-cancel", "headless-agent-cancel":
				v, err := a.dispatchAgent(context.Background(), "cancel-apply", json.RawMessage(`{}`))
				if err != nil || !v.(agent.CancelApplyResult).Accepted {
					t.Fatalf("cancel: %v %v", v, err)
				}
			case "headless-quit":
				d.call(func() { op.quit = true; a.cancelGUIConfigOperation(op) })
			default:
				d.call(func() { a.cancelGUIConfigOperation(op) })
			}
			var applyErr error
			select {
			case applyErr = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("apply did not finish")
			}
			select {
			case <-op.done:
			case <-time.After(20 * time.Second):
				t.Fatal("transaction did not release barrier")
			}
			if (scenario == "success") != (applyErr == nil) {
				t.Fatalf("apply result: %v", applyErr)
			}
			if scenario == "context-cancel" && !errors.Is(applyErr, context.Canceled) {
				t.Fatal(applyErr)
			}
			catalogAfter, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if err != nil {
				t.Fatal(err)
			}
			configAfter, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "external-catalog" {
				if string(catalogAfter) != "external edit" || !strings.Contains(applyErr.Error(), "restor") {
					t.Fatal("external edit not preserved", applyErr)
				}
			} else if scenario == "success" {
				if bytes.Equal(catalogBefore, catalogAfter) {
					t.Fatal("successful approval did not persist")
				}
			} else if !bytes.Equal(catalogBefore, catalogAfter) || !bytes.Equal(configBefore, configAfter) {
				t.Fatal("canceled application did not restore exact snapshots")
			}
			if scenario == "rollback-fails" && !strings.Contains(applyErr.Error(), "restoration failed") {
				t.Fatal("rollback failure was not reported", applyErr)
			}
			if scenario == "sensitive-error" && (strings.Contains(applyErr.Error(), "synthetic-secret") || !strings.Contains(applyErr.Error(), "restoration failed")) {
				t.Fatal("sensitive kernel diagnostic escaped or rollback failure was hidden", applyErr)
			}
		})
	}
}
