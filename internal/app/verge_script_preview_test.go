package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
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
		"profiles/global.js":  `function main(c){c.rules.unshift("DOMAIN,global.test,DIRECT");return c}`,
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
	a.tunBusy = true
	if err := a.checkVergeScriptDraft(draft); err != scriptpreview.ErrSourcesChanged {
		t.Fatal("TUN transition accepted")
	}
}
