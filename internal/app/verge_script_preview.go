package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptpreview"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/validation"
)

// vergeScriptDraft freezes the app-owned configuration on its event loop.
// It contains private subscription data and must never be serialized or logged.
type vergeScriptDraft struct {
	target, active        string
	item                  profile.CatalogItem
	catalog               profile.File
	base, activeEffective []byte
	hashes                map[string][32]byte
	state                 rewrite.State
	options               *kernelopts.Options
	status                core.Status
	tunSetting            bool
	chain                 *activeChain
	clock                 time.Time
}

type vergeScriptPreviewPages struct {
	before, after []string
	bytes         int
	expires       time.Time
}

func (a *App) finishVergeScriptPreview(d vergeScriptDraft, p scriptpreview.Prepared) (agent.VergeScriptPreview, error) {
	var result agent.VergeScriptPreview
	if err := a.checkVergeScriptDraft(d); err != nil {
		return result, err
	}
	now := time.Now()
	for id, preview := range a.agentScriptPreviews {
		if !preview.expires.After(now) {
			delete(a.agentScriptPreviews, id)
		}
	}
	if len(a.agentScriptPreviews) >= 32 {
		return result, errors.New("too many pending script previews")
	}
	bytes, err := previewRuleFootprint(p.BeforeRules, p.AfterRules)
	if err != nil {
		return result, err
	}
	used := 0
	for _, preview := range a.agentScriptPreviews {
		used += preview.bytes
	}
	for _, proposal := range a.agentProposals {
		if proposal.expires.After(now) {
			used += proposal.ruleBytes
		}
	}
	if bytes > maxPreviewRuleMemory-used {
		return result, errors.New("pending preview rules exceed the in-memory limit")
	}
	before, err := previewRulePage(p.BeforeRules, 0, 100)
	if err != nil {
		return result, err
	}
	after, err := previewRulePage(p.AfterRules, 0, 100)
	if err != nil {
		return result, err
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return result, err
	}
	id := hex.EncodeToString(token[:])
	expires := now.Add(2 * time.Minute)
	if a.agentScriptPreviews == nil {
		a.agentScriptPreviews = map[string]vergeScriptPreviewPages{}
	}
	a.agentScriptPreviews[id] = vergeScriptPreviewPages{before: p.BeforeRules, after: p.AfterRules, bytes: bytes, expires: expires}
	warnings := []string{
		"Read-only preview: scripts are not enabled and this preview cannot be applied.",
		"Scripts use a fixed preview time and deterministic random values; behavior can differ from Clash Verge.",
		"Agent-managed rules are applied after Verge scripts. Existing connections are not rerouted.",
		"Only top-level field names and rule lists are shown; inspect DNS, nodes and controller settings separately.",
	}
	if !d.item.Option.VergeExtensions {
		warnings = append(warnings, "This preview also includes archived Verge data extensions that are currently disabled.")
	}
	if d.target != d.active {
		warnings = append(warnings, "This profile is inactive.")
	}
	warnings = append(warnings, p.Validation.Warnings...)
	return agent.VergeScriptPreview{PreviewID: id, TargetProfile: d.target, ChangedFields: p.Changes.Fields, OtherChangedFields: p.Changes.OtherCount, RulesBefore: before, RulesAfter: after, Warnings: warnings, ExpiresAt: expires}, nil
}

func (a *App) vergeScriptPreviewRules(in agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) {
	p, ok := a.agentScriptPreviews[in.ProposalID]
	if !ok || !p.expires.After(time.Now()) {
		delete(a.agentScriptPreviews, in.ProposalID)
		return agent.PreviewRulesResult{}, errors.New("script preview missing or expired")
	}
	switch in.Stage {
	case "before":
		return previewRulePage(p.before, in.Offset, in.Limit)
	case "after":
		return previewRulePage(p.after, in.Offset, in.Limit)
	default:
		return agent.PreviewRulesResult{}, errors.New("stage must be before or after")
	}
}

// captureVergeScriptDraft must be called on the app event loop. Expensive
// script execution and offline validation happen outside the event loop.
func (a *App) captureVergeScriptDraft(target string) (vergeScriptDraft, error) {
	var d vergeScriptDraft
	if a.core == nil || a.profiles == nil || a.rewrites == nil {
		return d, errors.New("agent service is not ready")
	}
	if err := a.checkSettingsCurrent(); err != nil {
		return d, err
	}
	if err := a.rewrites.CheckCurrent(); err != nil {
		return d, err
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return d, err
		}
		value := a.kernelOptions.Snapshot()
		d.options = &value
	}
	d.status = a.core.Status()
	if !d.status.Running || a.tunBusy {
		return d, errors.New("core is stopped or TUN is changing")
	}
	if a.settings.TUN && (tunCIBlocked() || !a.tunAllowed()) {
		return d, tun.ErrNeedService
	}
	d.active = a.core.ProfileID()
	if target == "" {
		target = d.active
	}
	d.target = target
	var catalogHash [32]byte
	var err error
	d.catalog, catalogHash, err = a.profiles.LoadSnapshot()
	if err != nil {
		return d, err
	}
	found := false
	for _, item := range d.catalog.Items {
		if item.UID == target {
			d.item, found = item, true
			break
		}
	}
	if !found || d.item.Option.VergeArchive == "" || d.item.Option.VergeUID == "" {
		return d, errors.New("target has no Verge archive")
	}
	d.hashes = map[string][32]byte{filepath.Join(a.dir, "profiles.json"): catalogHash}
	var path string
	if target == d.active {
		path = filepath.Join(a.dir, "config.yaml")
		d.base, err = safepath.ReadFile(a.dir, "config.yaml")
		if err == nil {
			d.activeEffective, err = a.core.EffectiveConfig()
		}
	} else {
		d.base, path, err = readProfileFile(a.dir, d.item.File)
	}
	if err != nil {
		return vergeScriptDraft{}, err
	}
	d.hashes[path] = sha256.Sum256(d.base)
	if target != d.active {
		d.base = profile.EnsureMixedPort(d.base, 7897)
	}
	if a.kernelOptions != nil {
		path = filepath.Join(a.dir, "kernel-options.json")
		body, readErr := safepath.ReadFile(a.dir, "kernel-options.json")
		if readErr == nil {
			d.hashes[path] = sha256.Sum256(body)
		} else if errors.Is(readErr, os.ErrNotExist) {
			d.hashes[path] = [32]byte{}
		} else {
			return vergeScriptDraft{}, readErr
		}
	}
	d.state = a.rewrites.Snapshot()
	d.tunSetting, d.chain, d.clock = a.settings.TUN, a.chain.Load(), time.Now().UTC()
	return d, nil
}

func (d vergeScriptDraft) finalize(body []byte) ([]byte, error) {
	var err error
	body, err = profile.RemapVergeProviders(body, d.item.Option.VergeProviderPaths)
	if err != nil {
		return nil, err
	}
	body, err = tun.Compose(body, d.tunSetting, tun.DeviceName())
	if err != nil {
		return nil, err
	}
	body, err = composeProfileDNSFromCatalog(body, d.target, d.catalog)
	if err != nil {
		return nil, err
	}
	if rewrite.HasActive(d.state, d.target, d.clock) {
		body, _, err = rewrite.Compose(body, d.state, d.target, d.clock)
		if err != nil {
			return nil, err
		}
	}
	if d.options != nil {
		body, err = kernelopts.Compose(body, *d.options)
		if err != nil {
			return nil, err
		}
	}
	return composeActiveChain(body, d.target, d.chain)
}

// checkVergeScriptDraft must run on the app event loop after the filesystem
// sources have been checked. It is also required immediately before any apply.
func (a *App) checkVergeScriptDraft(d vergeScriptDraft) error {
	if a.core == nil || a.rewrites == nil || a.checkSettingsCurrent() != nil || a.rewrites.CheckCurrent() != nil {
		return scriptpreview.ErrSourcesChanged
	}
	if a.kernelOptions != nil && a.kernelOptions.CheckCurrent() != nil {
		return scriptpreview.ErrSourcesChanged
	}
	status := a.core.Status()
	if !status.Running || a.tunBusy || a.core.ProfileID() != d.active || a.rewrites.Snapshot().Revision != d.state.Revision || status.TUN != d.status.TUN || status.Mode != d.status.Mode || a.settings.TUN != d.tunSetting || a.chain.Load() != d.chain {
		return scriptpreview.ErrSourcesChanged
	}
	if (a.kernelOptions == nil) != (d.options == nil) || (d.options != nil && !reflect.DeepEqual(a.kernelOptions.Snapshot(), *d.options)) {
		return scriptpreview.ErrSourcesChanged
	}
	for _, connection := range d.state.Connections {
		if connection.ProfileID == d.target && connection.ExpiresAt.After(d.clock) && !connection.ExpiresAt.After(time.Now()) {
			return scriptpreview.ErrSourcesChanged
		}
	}
	return nil
}

// prepareVergeScript runs only outside the app event loop. It previews one
// profile, without persisting or applying a script selection.
func (a *App) prepareVergeScript(ctx context.Context, d vergeScriptDraft, selection migration.ScriptSelection) (scriptpreview.Prepared, error) {
	var empty scriptpreview.Prepared
	baseline, archivePath, archiveHash, err := migration.ComposeArchived(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, d.base)
	if err != nil {
		return empty, scriptpreview.ErrCandidate
	}
	d.hashes[archivePath] = archiveHash
	if !d.item.Option.VergeExtensions {
		baseline = d.base
	}
	baseline, err = d.finalize(baseline)
	if err != nil {
		return empty, scriptpreview.ErrFinalize
	}
	if d.target == d.active {
		baseline = d.activeEffective
	}
	return scriptpreview.Prepare(ctx, scriptpreview.PrepareInput{
		Root: a.dir, Archive: d.item.Option.VergeArchive, UID: d.item.Option.VergeUID, ProfileName: d.item.Name, Base: d.base, Baseline: baseline, Selection: selection, Clock: d.clock,
		Finalize: func(_ context.Context, body []byte) ([]byte, error) { return d.finalize(body) },
		Validate: func(ctx context.Context, body []byte) (validation.Result, error) {
			return validateConfigurations(ctx, a.dir, []validation.Config{{ID: d.target, Body: body}})
		},
		Check: func(ctx context.Context, _ scriptpreview.Candidate, checked validation.Result) error {
			for path, hash := range checked.Sources {
				if prev, ok := d.hashes[path]; ok && prev != hash {
					return scriptpreview.ErrSourcesChanged
				}
				d.hashes[path] = hash
			}
			if err := a.checkAgentSources(d.hashes); err != nil {
				return err
			}
			var checkErr error
			executed := false
			a.runOnMain(func() {
				executed = true
				if checkErr = ctx.Err(); checkErr == nil {
					checkErr = a.checkVergeScriptDraft(d)
				}
			})
			if !executed {
				return errors.New("application is shutting down")
			}
			return checkErr
		},
	})
}
