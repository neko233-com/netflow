package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptpreview"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestVergeScriptPreviewUsesOfflineValidationWithoutChangingCore(t *testing.T) {
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":       "current: p1\nitems:\n  - {uid: p1, type: local, name: Test, file: p1.yaml, option: {merge: m1, script: s1}}\n  - {uid: p2, type: local, name: Invalid, file: p2.yaml, option: {script: s2}}\n  - {uid: m1, type: merge, file: m1.yaml}\n  - {uid: Script, type: script, file: global.js}\n  - {uid: s1, type: script, file: profile.js}\n  - {uid: s2, type: script, file: bad.js}\n",
		"profiles/p1.yaml":    fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)),
		"profiles/m1.yaml":    "profile: {store-selected: true}\n",
		"profiles/p2.yaml":    "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n",
		"profiles/global.js":  `function main(c){c.rules.unshift("DOMAIN,global.test,DIRECT");c.tun.enable=true;c["mixed-port"]=1;c.mode="global";c["external-controller"]="0.0.0.0:9090";return c}`,
		"profiles/profile.js": `function main(c){c.rules.unshift("DOMAIN,profile.test,DIRECT");return c}`,
		"profiles/bad.js":     `function main(c){c.rules.unshift("DOMAIN,invalid.test,MissingPolicy");return c}`,
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
	if _, err := parsed.ImportVerge(dir); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatal("core did not start")
	}
	a.dispatch = func(fn func()) { fn() }
	draft, err := a.captureVergeScriptDraft("")
	if err != nil {
		t.Fatal(err)
	}
	before, err := a.core.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := a.prepareVergeScript(context.Background(), draft, migration.ScriptSelection{Global: true, Profile: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.AfterRules) != 3 || prepared.AfterRules[0] != "DOMAIN,profile.test,DIRECT" || prepared.AfterRules[1] != "DOMAIN,global.test,DIRECT" {
		t.Fatalf("script rules not composed: %v", prepared.AfterRules)
	}
	if bytes.Contains(prepared.Effective, []byte("0.0.0.0:9090")) || a.core.Status().TUN {
		t.Fatal("script modified protected control fields")
	}
	after, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed active core")
	}
	raw, _ := json.Marshal(agent.VergeScriptPreviewArgs{Global: true, Profile: true})
	value, err := a.dispatchAgent(context.Background(), "verge-script-preview", raw)
	if err != nil {
		t.Fatal(err)
	}
	preview := value.(agent.VergeScriptPreview)
	if preview.PreviewID == "" || preview.RulesAfter.Total != 3 {
		t.Fatal("incomplete agent preview")
	}
	if _, err := a.agentApply(preview.PreviewID); err == nil {
		t.Fatal("read-only preview accepted as an apply proposal")
	}
	configArgs, _ := json.Marshal(agent.VergeScriptConfigArgs{PreviewID: preview.PreviewID, Stage: "after"})
	value, err = a.dispatchAgent(context.Background(), "verge-script-preview-config", configArgs)
	if err != nil || !strings.Contains(value.(agent.VergeScriptConfigPage).Text, "DOMAIN,profile.test,DIRECT") || strings.Contains(value.(agent.VergeScriptConfigPage).Text, "0.0.0.0:9090") {
		t.Fatal("explicit config preview incorrect", err)
	}
	pageArgs, _ := json.Marshal(agent.PreviewRulesArgs{ProposalID: preview.PreviewID, Stage: "after", Offset: 1, Limit: 1})
	value, err = a.dispatchAgent(context.Background(), "verge-script-preview-rules", pageArgs)
	if err != nil || value.(agent.PreviewRulesResult).Rules[0] != "DOMAIN,global.test,DIRECT" {
		t.Fatal("preview paging failed", err)
	}
	cancelArgs, _ := json.Marshal(agent.ApplyArgs{ProposalID: preview.PreviewID})
	value, err = a.dispatchAgent(context.Background(), "verge-script-preview-cancel", cancelArgs)
	if err != nil || !value.(agent.ActionResult).OK {
		t.Fatal("preview cancellation failed", err)
	}
	if _, err := a.dispatchAgent(context.Background(), "verge-script-preview-rules", pageArgs); err == nil {
		t.Fatal("canceled preview is still available")
	}
	bridge, err := agent.Start(dir, a.dispatchAgent)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.Client{Dir: dir}
	var viaBridge agent.VergeScriptPreview
	err = client.Call(context.Background(), "verge-script-preview", agent.VergeScriptPreviewArgs{Global: true, Profile: true}, &viaBridge)
	if err != nil || viaBridge.RulesAfter.Total != 3 {
		_ = bridge.Close()
		t.Fatal("live agent bridge preview failed", err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	var inactive string
	for _, item := range catalog.Items {
		if item.Name == "Invalid" {
			inactive = item.UID
		}
	}
	if inactive == "" {
		t.Fatal("inactive imported profile missing")
	}
	badDraft, err := a.captureVergeScriptDraft(inactive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.prepareVergeScript(context.Background(), badDraft, migration.ScriptSelection{Profile: true}); !errors.Is(err, scriptpreview.ErrValidation) {
		t.Fatalf("invalid script output accepted or not validated: %v", err)
	}
	// Exercise the persisted-output runtime building block. There is no public
	// script apply operation until the transaction and rollback paths are ready.
	approval, err := scriptapproval.Store(context.Background(), dir, prepared.Candidate, draft.base, draft.item.Name)
	if err != nil {
		t.Fatal(err)
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	for i := range catalog.Items {
		if catalog.Items[i].UID == draft.target {
			catalog.Items[i].Option.VergeScriptApproval = &approval
			catalog.Items[i].Option.VergeExtensions = true
		}
	}
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Reload(); err != nil {
		t.Fatal("cached script reload failed", err)
	}
	active, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Contains(active, []byte("DOMAIN,profile.test,DIRECT")) {
		t.Fatal("approved output not used", err)
	}
	if bytes.Contains(active, []byte("0.0.0.0:9090")) || a.core.Status().TUN || a.core.Status().Mode == "global" {
		t.Fatal("cached script modified protected runtime controls")
	}
	if err := a.core.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Start(dir); err != nil {
		t.Fatal("restart with cached script failed", err)
	}
	active, err = a.core.EffectiveConfig()
	if err != nil || !bytes.Contains(active, []byte("DOMAIN,profile.test,DIRECT")) {
		t.Fatal("script output was not restored on restart", err)
	}
	proposal, err := a.agentPreview(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,agent.test,DIRECT"}}})
	if err != nil || len(proposal.RulesAfter) == 0 || proposal.RulesAfter[0] != "DOMAIN,agent.test,DIRECT" {
		t.Fatal("Agent rule did not override script", err)
	}
	resolved, err := scriptapproval.ResolveSnapshot(context.Background(), dir, approval, draft.base, draft.item.Name, draft.item.Option.VergeArchive, draft.item.Option.VergeUID)
	if err != nil {
		t.Fatal(err)
	}
	var cache string
	for path := range resolved.Sources {
		if strings.Contains(path, "verge-script-outputs") {
			cache = path
		}
	}
	if cache == "" {
		t.Fatal("cache was not bound as a preview source")
	}
	if err := os.WriteFile(cache, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("changed cache accepted by Agent apply")
	}
	if err := a.core.Reload(); err == nil {
		t.Fatal("changed cached output was loaded")
	}
	stillActive, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Equal(active, stillActive) {
		t.Fatal("failed reload changed running core", err)
	}
	a.tunBusy = true
	if err := a.checkVergeScriptDraft(draft); err != scriptpreview.ErrSourcesChanged {
		t.Fatal("TUN transition accepted")
	}
}
