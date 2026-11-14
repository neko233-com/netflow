package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestImportedVergeRulesRunBeforeScriptsAndRemainSeparateFromAgent(t *testing.T) {
	for _, defaultRules := range []bool{false, true} {
		t.Run(fmt.Sprintf("default-%v", defaultRules), func(t *testing.T) {
			source := t.TempDir()
			if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
				t.Fatal(err)
			}
			ruleID, ruleOption := "r1", "rules: r1, "
			if defaultRules {
				ruleID, ruleOption = "Rules", ""
			}
			files := map[string]string{
				"profiles.yaml":      fmt.Sprintf("current: p\nitems:\n  - {uid: p, type: local, name: Test, file: p.yaml, option: {%sscript: s}}\n  - {uid: %s, type: rules, file: r.yaml}\n  - {uid: Script, type: script, file: global.js}\n  - {uid: s, type: script, file: local.js}\n", ruleOption, ruleID),
				"profiles/p.yaml":    fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)),
				"profiles/r.yaml":    "prepend: ['DOMAIN,verge.test,DIRECT']\nappend: ['DOMAIN,after-match.test,DIRECT']\n",
				"profiles/global.js": `function main(c){if(c.rules[0]!=="DOMAIN,verge.test,DIRECT")throw Error();c.rules[0]="DOMAIN,global.test,DIRECT";return c}`,
				"profiles/local.js":  `function main(c){if(c.rules[0]!=="DOMAIN,global.test,DIRECT")throw Error();c.rules.unshift("DOMAIN,local.test,DIRECT");return c}`,
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			imported, err := migration.ReadVerge(source)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if _, err := imported.ImportVerge(dir); err != nil {
				t.Fatal(err)
			}
			a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
			if err := a.Prepare(); err != nil {
				t.Fatal(err)
			}
			defer a.core.Stop()
			a.dispatch = func(fn func()) { fn() }
			catalog, err := a.profiles.Load()
			if err != nil || len(catalog.Items) != 1 || !catalog.Items[0].Option.VergeRulesBeforeScripts {
				t.Fatal("new ordering was not recorded", err)
			}
			id := catalog.Items[0].UID
			if len(a.rewrites.Snapshot().Profiles[id].Prepend) != 0 {
				t.Fatal("Verge rule was inserted into Agent rewrite state")
			}
			before, err := a.core.EffectiveConfig()
			if err != nil || !bytes.Contains(before, []byte("DOMAIN,verge.test,DIRECT")) {
				t.Fatal("Verge rules missing before script approval", err)
			}
			input, _ := json.Marshal(agent.VergeScriptPreviewArgs{ProfileID: id, Global: true, Profile: true})
			value, err := a.dispatchAgent(context.Background(), "verge-script-preview", input)
			if err != nil {
				t.Fatal("script did not observe migrated rules", err)
			}
			preview := value.(agent.VergeScriptPreview)
			joined := strings.Join(preview.RulesAfter.Rules, "|")
			if joined != "DOMAIN,local.test,DIRECT|DOMAIN,global.test,DIRECT|MATCH,DIRECT|DOMAIN,after-match.test,DIRECT" {
				t.Fatalf("wrong composed rule order: %s", joined)
			}
			apply, _ := json.Marshal(agent.ApplyArgs{ProposalID: preview.PreviewID})
			if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err != nil {
				t.Fatal(err)
			}
			effective, err := a.core.EffectiveConfig()
			if err != nil || !bytes.Contains(effective, []byte("DOMAIN,local.test,DIRECT")) || bytes.Contains(effective, []byte("DOMAIN,verge.test,DIRECT")) {
				t.Fatal("approved output reintroduced a pre-script rule", err)
			}
			proposal, err := a.agentPreview(agent.Change{Scope: "profile", ProfileID: id, Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,agent.test,DIRECT"}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.agentApply(proposal.ProposalID); err != nil {
				t.Fatal(err)
			}
			effective, err = a.core.EffectiveConfig()
			if err != nil || !bytes.Contains(effective, []byte("DOMAIN,agent.test,DIRECT")) || bytes.Contains(effective, []byte("DOMAIN,verge.test,DIRECT")) {
				t.Fatal("Agent rules were not applied after scripts", err)
			}
			disable, _ := json.Marshal(agent.VergeScriptPreviewArgs{ProfileID: id})
			value, err = a.dispatchAgent(context.Background(), "verge-script-preview", disable)
			if err != nil {
				t.Fatal(err)
			}
			apply, _ = json.Marshal(agent.ApplyArgs{ProposalID: value.(agent.VergeScriptPreview).PreviewID})
			if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err != nil {
				t.Fatal(err)
			}
			effective, err = a.core.EffectiveConfig()
			if err != nil || !bytes.Contains(effective, []byte("DOMAIN,verge.test,DIRECT")) || bytes.Contains(effective, []byte("DOMAIN,local.test,DIRECT")) {
				t.Fatal("disabling scripts lost original rules", err)
			}
			rollback, _ := json.Marshal(agent.ProfileArgs{ProfileID: id})
			value, err = a.dispatchAgent(context.Background(), "verge-script-rollback-preview", rollback)
			if err != nil {
				t.Fatal(err)
			}
			apply, _ = json.Marshal(agent.ApplyArgs{ProposalID: value.(agent.VergeScriptPreview).PreviewID})
			if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err != nil {
				t.Fatal(err)
			}
			effective, err = a.core.EffectiveConfig()
			if err != nil || !bytes.Contains(effective, []byte("DOMAIN,local.test,DIRECT")) || bytes.Contains(effective, []byte("DOMAIN,verge.test,DIRECT")) {
				t.Fatal("rollback lost approved script ordering", err)
			}
			changed, snapshot, err := a.profiles.LoadForUpdate()
			if err != nil {
				t.Fatal(err)
			}
			changed.Items[0].Option.VergeRulesBeforeScripts = false
			if err := a.profiles.SaveIfUnchanged(changed, snapshot); err != nil {
				t.Fatal(err)
			}
			if err := a.core.Reload(); err == nil {
				t.Fatal("changed rule ordering reused an old approval")
			}
			if err := a.profiles.RestoreSnapshotIfUnchanged(changed, snapshot); err != nil {
				t.Fatal(err)
			}
			if err := a.core.Reload(); err != nil {
				t.Fatal(err)
			}
			if !defaultRules {
				catalog, snapshot, err := a.profiles.LoadForUpdate()
				if err != nil {
					t.Fatal(err)
				}
				oldURL := "https://old.example/sub?token=old-secret"
				catalog.Items[0].Type, catalog.Items[0].URL = "remote", oldURL
				if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
					t.Fatal(err)
				}
				body, _, err := readProfileFile(a.dir, catalog.Items[0].File)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte("MATCH,DIRECT"), []byte("DOMAIN,new-sub.test,DIRECT', 'MATCH,DIRECT"), 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
				defer server.Close()
				newURL := server.URL + "/sub?token=new-secret"
				badArgs, _ := json.Marshal(agent.VergeScriptUpdateArgs{ProfileID: id, URL: "ftp://invalid.test/?token=bad-secret"})
				if _, err := a.dispatchAgent(context.Background(), "verge-script-update-preview", badArgs); err == nil || strings.Contains(err.Error(), "bad-secret") {
					t.Fatal("invalid replacement URL was accepted or exposed", err)
				}
				args, _ := json.Marshal(agent.VergeScriptUpdateArgs{ProfileID: id, URL: newURL})
				value, err := a.dispatchAgent(context.Background(), "verge-script-update-preview", args)
				if err != nil {
					t.Fatal("replacement preview failed", err)
				}
				p := value.(agent.VergeScriptPreview)
				encoded, _ := json.Marshal(p)
				if strings.Contains(string(encoded), "secret") || !strings.Contains(strings.Join(p.Warnings, " "), "replaces the subscription URL") {
					t.Fatal("replacement preview leaked a secret or omitted its warning")
				}
				beforeCatalog, err := a.profiles.Load()
				if err != nil || beforeCatalog.Items[0].URL != oldURL {
					t.Fatal("preview changed subscription URL", err)
				}
				changedCatalog, original, err := a.profiles.LoadForUpdate()
				if err != nil {
					t.Fatal(err)
				}
				changedCatalog.Items[0].Description = "external edit"
				if err := a.profiles.SaveIfUnchanged(changedCatalog, original); err != nil {
					t.Fatal(err)
				}
				apply, _ = json.Marshal(agent.ApplyArgs{ProposalID: p.PreviewID})
				if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err == nil {
					t.Fatal("stale URL preview was applied")
				}
				if err := a.profiles.RestoreSnapshotIfUnchanged(changedCatalog, original); err != nil {
					t.Fatal(err)
				}
				value, err = a.dispatchAgent(context.Background(), "verge-script-update-preview", args)
				if err != nil {
					t.Fatal(err)
				}
				p = value.(agent.VergeScriptPreview)
				apply, _ = json.Marshal(agent.ApplyArgs{ProposalID: p.PreviewID})
				if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err != nil {
					t.Fatal("replacement apply failed", err)
				}
				afterCatalog, err := a.profiles.Load()
				if err != nil || afterCatalog.Items[0].URL != newURL {
					t.Fatal("replacement URL was not committed", err)
				}
				effective, err = a.core.EffectiveConfig()
				if err != nil || !bytes.Contains(effective, []byte("DOMAIN,new-sub.test,DIRECT")) {
					t.Fatal("replacement content was not applied", err)
				}
				value, err = a.dispatchAgent(context.Background(), "verge-script-rollback-preview", rollback)
				if err != nil {
					t.Fatal(err)
				}
				apply, _ = json.Marshal(agent.ApplyArgs{ProposalID: value.(agent.VergeScriptPreview).PreviewID})
				if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", apply); err != nil {
					t.Fatal(err)
				}
				afterCatalog, err = a.profiles.Load()
				if err != nil || afterCatalog.Items[0].URL != oldURL {
					t.Fatal("rollback did not restore original URL", err)
				}
			}
		})
	}
}
