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
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptpreview"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

type scriptCatalogChangeEngine struct {
	coreEngine
	app *App
}

func (e *scriptCatalogChangeEngine) Reload() error {
	catalog, err := e.app.profiles.Load()
	if err != nil {
		return err
	}
	catalog.Items[0].Description = "concurrent external edit"
	if err := e.app.profiles.Save(catalog); err != nil {
		return err
	}
	return errors.New("synthetic reload failure")
}

func TestVergeScriptCacheCleanupRejectsMissingCatalog(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "verge-script-outputs")
	if err := os.Mkdir(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cacheDir, strings.Repeat("a", 64)+".json")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{})
	a.dir = dir
	a.profiles = profile.NewStore(dir)
	a.dispatch = func(fn func()) { fn() }
	if _, err := a.dispatchAgent(context.Background(), "verge-script-cache-prune", json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing catalog accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("cache deleted without catalog", err)
	}
}

func TestVergeScriptPreviewUsesOfflineValidationWithoutChangingCore(t *testing.T) {
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":        "current: p1\nitems:\n  - {uid: p1, type: local, name: Test, file: p1.yaml, option: {merge: m1, script: s1}}\n  - {uid: p2, type: local, name: Invalid, file: p2.yaml, option: {script: s2}}\n  - {uid: p3, type: local, name: Inactive, file: p3.yaml, option: {script: s3}}\n  - {uid: m1, type: merge, file: m1.yaml}\n  - {uid: Script, type: script, file: global.js}\n  - {uid: s1, type: script, file: profile.js}\n  - {uid: s2, type: script, file: bad.js}\n  - {uid: s3, type: script, file: inactive.js}\n",
		"profiles/p1.yaml":     fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)),
		"profiles/m1.yaml":     "profile: {store-selected: true}\n",
		"profiles/p2.yaml":     "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n",
		"profiles/p3.yaml":     "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n",
		"profiles/global.js":   `function main(c){c.rules.unshift("DOMAIN,global.test,DIRECT");c.tun.enable=true;c["mixed-port"]=1;c.mode="global";c["external-controller"]="0.0.0.0:9090";return c}`,
		"profiles/profile.js":  `function main(c){c.rules.unshift("DOMAIN,profile.test,DIRECT");return c}`,
		"profiles/bad.js":      `function main(c){c.rules.unshift("DOMAIN,invalid.test,MissingPolicy");return c}`,
		"profiles/inactive.js": `function main(c){c.rules.unshift("DOMAIN,inactive.test,DIRECT");return c}`,
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
	// Commit is still internal until the explicit rollback preview is wired.
	scriptProposal := a.agentScriptPreviews[viaBridge.PreviewID]
	ready, err := a.prepareVergeScriptCommit(context.Background(), scriptProposal)
	if err != nil {
		t.Fatal(err)
	}
	_, oldCatalog, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	a.tunBusy = true
	if _, err := a.finishVergeScriptCommit(context.Background(), ready); err == nil {
		t.Fatal("script apply accepted a TUN transition")
	}
	a.tunBusy = false
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.finishVergeScriptCommit(canceled, ready); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled script apply was accepted", err)
	}
	changed, previous, err := a.profiles.LoadForUpdate()
	if err != nil {
		t.Fatal(err)
	}
	changed.Items[0].Description = "synthetic external change"
	if err := a.profiles.SaveIfUnchanged(changed, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := a.finishVergeScriptCommit(context.Background(), ready); err == nil {
		t.Fatal("script apply accepted a changed catalog")
	}
	if err := a.profiles.RestoreSnapshotIfUnchanged(changed, previous); err != nil {
		t.Fatal(err)
	}
	coreBeforeFailure := a.core
	a.core = &scriptCatalogChangeEngine{coreEngine: coreBeforeFailure, app: a}
	if _, err := a.finishVergeScriptCommit(context.Background(), ready); err == nil {
		t.Fatal("reload failure with external edit was accepted")
	}
	modified, err := a.profiles.Load()
	if err != nil || modified.Items[0].Description != "concurrent external edit" {
		t.Fatal("rollback overwrote an external catalog edit", err)
	}
	if err := a.profiles.RestoreSnapshotIfUnchanged(modified, oldCatalog); err != nil {
		t.Fatal(err)
	}
	a.core = &chainFailReloadEngine{coreEngine: coreBeforeFailure, failures: 1}
	if _, err := a.finishVergeScriptCommit(context.Background(), ready); err == nil {
		t.Fatal("injected reload failure accepted")
	}
	a.core = coreBeforeFailure
	_, restoredCatalog, err := a.profiles.LoadForUpdate()
	if err != nil || !bytes.Equal(oldCatalog, restoredCatalog) {
		t.Fatal("failed apply did not restore exact catalog", err)
	}
	if current, err := a.core.EffectiveConfig(); err != nil || !bytes.Equal(before, current) {
		t.Fatal("failed apply did not restore core", err)
	}
	if active, err := a.finishVergeScriptCommit(context.Background(), ready); err != nil || !active {
		t.Fatal("script commit failed", err)
	}
	approval := *ready.approval
	commitDraft := ready.proposal.draft
	listing, err := a.agentProfiles()
	if err != nil {
		t.Fatal(err)
	}
	var visible bool
	for _, item := range listing.Profiles {
		if item.ID == draft.target {
			visible = item.VergeArchive && item.VergeGlobalScript && item.VergeProfileScript && item.VergeScriptRollback
		}
	}
	if !visible {
		t.Fatal("Agent profile list omitted script status")
	}
	active, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Contains(active, []byte("DOMAIN,profile.test,DIRECT")) {
		t.Fatal("approved output not used", err)
	}
	if bytes.Contains(active, []byte("0.0.0.0:9090")) || a.core.Status().TUN || a.core.Status().Mode == "global" {
		t.Fatal("cached script modified protected runtime controls")
	}
	updateDraft, err := a.captureVergeScriptDraft(draft.target)
	if err != nil {
		t.Fatal(err)
	}
	updateSource, err := a.snapshotProfileSource(updateDraft.item.File)
	if err != nil {
		t.Fatal(err)
	}
	downloaded := bytes.Replace(updateDraft.base, []byte("MATCH,DIRECT"), []byte("DOMAIN,new-subscription.test,DIRECT"), 1)
	updatedPreview, err := a.prepareVergeScriptUpdate(context.Background(), updateDraft, updateSource, downloaded)
	if err != nil {
		t.Fatal("subscription script update preview failed", err)
	}
	if !bytes.Contains(updatedPreview.Effective, []byte("DOMAIN,new-subscription.test,DIRECT")) || !bytes.Contains(updatedPreview.Effective, []byte("DOMAIN,profile.test,DIRECT")) || !bytes.Contains(updatedPreview.Baseline, []byte("DOMAIN,profile.test,DIRECT")) {
		t.Fatal("subscription update preview omitted existing script or new subscription rules")
	}
	if current, err := a.core.EffectiveConfig(); err != nil || !bytes.Equal(active, current) {
		t.Fatal("subscription update preview changed the running core", err)
	}
	if _, err := a.prepareVergeScriptUpdate(context.Background(), updateDraft, updateSource, []byte("invalid: [")); err == nil {
		t.Fatal("invalid subscription was accepted for script update")
	}
	staleSource := updateSource
	staleSource.hash[0] ^= 1
	if _, err := a.prepareVergeScriptUpdate(context.Background(), updateDraft, staleSource, downloaded); !errors.Is(err, scriptpreview.ErrSourcesChanged) {
		t.Fatal("download based on a stale subscription snapshot was accepted", err)
	}
	// Preview and commit the previous data-only configuration, then preview
	// the reverse transition. Both directions go through offline validation.
	for step := 0; step < 2; step++ {
		raw, _ := json.Marshal(agent.ProfileArgs{ProfileID: draft.target})
		value, err := a.dispatchAgent(context.Background(), "verge-script-rollback-preview", raw)
		if err != nil {
			t.Fatal("rollback preview failed", err)
		}
		rbPreview := value.(agent.VergeScriptPreview)
		if rbPreview.Operation != "rollback" {
			t.Fatal("rollback preview operation missing")
		}
		applyRaw, _ := json.Marshal(agent.ApplyArgs{ProposalID: rbPreview.PreviewID})
		value, err = a.dispatchAgent(context.Background(), "verge-script-apply", applyRaw)
		if err != nil || !value.(agent.VergeScriptApplyResult).Applied || !value.(agent.VergeScriptApplyResult).Active {
			t.Fatal("rollback apply failed", err)
		}
		if _, err := a.dispatchAgent(context.Background(), "verge-script-apply", applyRaw); err == nil {
			t.Fatal("script preview applied twice")
		}
		current, err := a.core.EffectiveConfig()
		if err != nil {
			t.Fatal(err)
		}
		contains := bytes.Contains(current, []byte("DOMAIN,profile.test,DIRECT"))
		if contains != (step == 1) {
			t.Fatal("rollback did not restore exact script setting")
		}
	}
	// Explicitly preview disabling all scripts, then restore them with a new
	// preview. Existing connections and host TUN are not touched by the test.
	for step := 0; step < 2; step++ {
		request := agent.VergeScriptPreviewArgs{ProfileID: draft.target, Global: step == 1, Profile: step == 1}
		raw, _ := json.Marshal(request)
		value, err := a.dispatchAgent(context.Background(), "verge-script-preview", raw)
		if err != nil {
			t.Fatal("disable/enable preview failed", err)
		}
		preview := value.(agent.VergeScriptPreview)
		if step == 0 && preview.Operation != "disable" {
			t.Fatal("disable operation missing")
		}
		applyRaw, _ := json.Marshal(agent.ApplyArgs{ProposalID: preview.PreviewID})
		value, err = a.dispatchAgent(context.Background(), "verge-script-apply", applyRaw)
		if err != nil || !value.(agent.VergeScriptApplyResult).Applied {
			t.Fatal("disable/enable apply failed", err)
		}
		current, err := a.core.EffectiveConfig()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(current, []byte("DOMAIN,profile.test,DIRECT")) != (step == 1) {
			t.Fatal("disable/enable output incorrect")
		}
	}
	catalog, err = a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range catalog.Items {
		if item.UID == draft.target {
			if item.Option.VergeScriptApproval == nil {
				t.Fatal("enabled script approval missing")
			}
			approval = *item.Option.VergeScriptApproval
		}
	}
	var other string
	for _, item := range catalog.Items {
		if item.Name == "Inactive" {
			other = item.UID
		}
	}
	if other == "" {
		t.Fatal("inactive script profile missing")
	}
	beforeInactive, err := a.core.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	otherArgs, _ := json.Marshal(agent.VergeScriptPreviewArgs{ProfileID: other, Profile: true})
	value, err = a.dispatchAgent(context.Background(), "verge-script-preview", otherArgs)
	if err != nil {
		t.Fatal("inactive preview failed", err)
	}
	otherPreview := value.(agent.VergeScriptPreview)
	otherApply, _ := json.Marshal(agent.ApplyArgs{ProposalID: otherPreview.PreviewID})
	value, err = a.dispatchAgent(context.Background(), "verge-script-apply", otherApply)
	if err != nil || !value.(agent.VergeScriptApplyResult).Applied || value.(agent.VergeScriptApplyResult).Active {
		t.Fatal("inactive script apply failed", err)
	}
	unchanged, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Equal(beforeInactive, unchanged) {
		t.Fatal("inactive apply changed running core", err)
	}
	if err := a.UseProfile(other); err != nil {
		t.Fatal("could not activate approved inactive profile", err)
	}
	selected, err := a.core.EffectiveConfig()
	if err != nil || !bytes.Contains(selected, []byte("DOMAIN,inactive.test,DIRECT")) {
		t.Fatal("inactive script output did not activate", err)
	}
	if err := a.UseProfile(draft.target); err != nil {
		t.Fatal("could not restore original profile", err)
	}
	value, err = a.dispatchAgent(context.Background(), "verge-script-cache-prune", json.RawMessage(`{}`))
	if err != nil || value.(agent.VergeScriptCachePruneResult).Removed < 1 {
		t.Fatal("unreferenced script cache was not pruned", err)
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
	resolved, err := scriptapproval.ResolveSnapshot(context.Background(), dir, approval, commitDraft.base, commitDraft.item.Name, commitDraft.item.Option.VergeArchive, commitDraft.item.Option.VergeUID)
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
	archive := filepath.Join(dir, commitDraft.item.Option.VergeArchive)
	if err := os.Rename(archive, archive+".missing"); err != nil {
		t.Fatal(err)
	}
	if err := a.core.Stop(); err != nil {
		t.Fatal(err)
	}
	state := a.rewrites.Snapshot()
	state.Connections = append(state.Connections, rewrite.Connection{ID: "expired-recovery-fixture", ProfileID: draft.target, Rule: "DOMAIN,expired.test,DIRECT", ExpiresAt: time.Now().Add(-time.Minute)})
	if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "agent-rules.json")
	rulesBefore, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	recoveryCtx, cancelRecovery := context.WithCancel(context.Background())
	defer cancelRecovery()
	recoveryApp := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	readyStatus := make(chan core.Status, 1)
	finished := make(chan error, 1)
	go func() {
		finished <- recoveryApp.RunHeadless(recoveryCtx, HeadlessOptions{AllowStopped: true, ReadyStatus: func(status core.Status) { readyStatus <- status }})
	}()
	select {
	case status := <-readyStatus:
		if status.Running || status.TUN {
			t.Fatal("recovery started a core or TUN")
		}
	case err := <-finished:
		t.Fatal("recovery service exited", err)
	case <-time.After(15 * time.Second):
		t.Fatal("recovery service did not start")
	}
	time.Sleep(1200 * time.Millisecond)
	rulesDuring, err := os.ReadFile(rulesPath)
	if err != nil || !bytes.Equal(rulesBefore, rulesDuring) {
		t.Fatal("recovery mode changed Agent rule state", err)
	}
	var recovery agent.VergeScriptPreview
	err = client.Call(context.Background(), "verge-script-preview", agent.VergeScriptPreviewArgs{ProfileID: draft.target}, &recovery)
	if err != nil {
		t.Fatal("missing archive recovery preview failed", err)
	}
	if recovery.Operation != "recover-disable" {
		t.Fatal("recovery scope not reported")
	}
	var applied agent.VergeScriptApplyResult
	err = client.Call(context.Background(), "verge-script-apply", agent.ApplyArgs{ProposalID: recovery.PreviewID}, &applied)
	if err != nil || !applied.Applied || applied.CoreRunning {
		t.Fatal("missing archive recovery failed", err)
	}
	cancelRecovery()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("recovery service shutdown failed", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("recovery service did not shut down")
	}
	if err := a.core.Start(dir); err != nil {
		t.Fatal("core could not start after offline recovery", err)
	}
	recovered, err := a.core.EffectiveConfig()
	if err != nil || bytes.Contains(recovered, []byte("DOMAIN,profile.test,DIRECT")) || a.core.Status().TUN {
		t.Fatal("recovery did not restore raw subscription safely", err)
	}
	a.tunBusy = true
	if err := a.checkVergeScriptDraft(draft); err != scriptpreview.ErrSourcesChanged {
		t.Fatal("TUN transition accepted")
	}
}
