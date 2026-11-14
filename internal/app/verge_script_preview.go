package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptmeta"
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
	baselineUnknown       *bool
}

type vergeScriptPreviewPages struct {
	before, after             []string
	beforeConfig, afterConfig []byte
	bytes                     int
	expires                   time.Time
	draft                     vergeScriptDraft
	prepared                  scriptpreview.Prepared
	rollback                  bool
	rollbackTarget            *scriptmeta.Previous
	update                    *vergeSubscriptionUpdate
}

func (a *App) previewVergeScriptAsync(in agent.VergeScriptPreviewArgs, done func(agent.VergeScriptPreview, error)) func() {
	return a.previewVergeScriptOperationAsync("verge-script-preview", in, done)
}

func (a *App) previewVergeScriptRollbackAsync(id string, done func(agent.VergeScriptPreview, error)) func() {
	return a.previewVergeScriptOperationAsync("verge-script-rollback-preview", agent.ProfileArgs{ProfileID: id}, done)
}

func (a *App) previewVergeScriptUpdateAsync(id string, done func(agent.VergeScriptPreview, error)) func() {
	return a.previewVergeScriptOperationAsync("verge-script-update-preview", agent.ProfileArgs{ProfileID: id}, done)
}

func (a *App) previewVergeScriptURLAsync(id, url string, done func(agent.VergeScriptPreview, error)) func() {
	return a.previewVergeScriptOperationAsync("verge-script-update-preview", agent.VergeScriptUpdateArgs{ProfileID: id, URL: url}, done)
}

func (a *App) previewVergeScriptOperationAsync(method string, in any, done func(agent.VergeScriptPreview, error)) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		body, err := json.Marshal(in)
		var value any
		if err == nil {
			value, err = a.dispatchAgent(ctx, method, body)
		}
		var result agent.VergeScriptPreview
		if err == nil {
			var ok bool
			result, ok = value.(agent.VergeScriptPreview)
			if !ok {
				err = errors.New("invalid script preview result")
			}
		}
		a.runOnMain(func() {
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
	return cancel
}

func (a *App) applyVergeScriptAsync(id string, done func(agent.VergeScriptApplyResult, error)) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		body, err := json.Marshal(agent.ApplyArgs{ProposalID: id})
		var value any
		if err == nil {
			value, err = a.dispatchAgent(ctx, "verge-script-apply", body)
		}
		var result agent.VergeScriptApplyResult
		if err == nil {
			var ok bool
			result, ok = value.(agent.VergeScriptApplyResult)
			if !ok {
				err = errors.New("invalid script apply result")
			}
		}
		a.runOnMain(func() {
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
	return cancel
}

func (a *App) pruneVergeScriptCacheAsync(done func(agent.VergeScriptCachePruneResult, error)) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		value, err := a.dispatchAgent(ctx, "verge-script-cache-prune", json.RawMessage(`{}`))
		var result agent.VergeScriptCachePruneResult
		if err == nil {
			var ok bool
			result, ok = value.(agent.VergeScriptCachePruneResult)
			if !ok {
				err = errors.New("invalid cache cleanup result")
			}
		}
		a.runOnMain(func() {
			done(result, err)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
	return cancel
}

func (a *App) finishVergeScriptPreview(d vergeScriptDraft, p scriptpreview.Prepared, rollback bool, update *vergeSubscriptionUpdate) (agent.VergeScriptPreview, error) {
	var result agent.VergeScriptPreview
	if err := a.checkVergeScriptDraft(d); err != nil {
		return result, err
	}
	if rollback {
		if update != nil {
			return result, scriptpreview.ErrSourcesChanged
		}
		var err error
		update, err = a.rollbackSubscription(d)
		if err != nil {
			return result, err
		}
		if update != nil && sha256.Sum256(profile.EnsureMixedPort(update.body, 7897)) != p.Candidate.BaseSHA256 {
			return result, scriptpreview.ErrSourcesChanged
		}
	} else if update != nil && (update.snapshot.File != "" || sha256.Sum256(profile.EnsureMixedPort(update.body, 7897)) != p.Candidate.BaseSHA256) {
		return result, scriptpreview.ErrSourcesChanged
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
	bytes += len(p.Baseline) + len(p.Effective)
	bytes += len(p.Candidate.Body) + len(d.base) + len(d.activeEffective)
	if update != nil {
		bytes += len(update.body) + len(update.snapshot.File) + len(update.snapshot.URL)
	}
	catalogBytes, err := json.Marshal(d.catalog)
	if err != nil || len(catalogBytes) > 8<<20 {
		return result, errors.New("profile catalog is too large for script preview")
	}
	stateBytes, err := json.Marshal(d.state)
	if err != nil || len(stateBytes) > 8<<20 {
		return result, errors.New("rule state is too large for script preview")
	}
	bytes += len(catalogBytes) + len(stateBytes)
	for path := range d.hashes {
		bytes += len(path) + 64
	}
	for path := range p.Validation.Sources {
		bytes += len(path) + 64
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
	for _, connection := range d.state.Connections {
		if connection.ProfileID == d.target && connection.ExpiresAt.After(d.clock) && connection.ExpiresAt.Before(expires) {
			expires = connection.ExpiresAt
		}
	}
	if !expires.After(now) {
		return result, scriptpreview.ErrSourcesChanged
	}
	if a.agentScriptPreviews == nil {
		a.agentScriptPreviews = map[string]vergeScriptPreviewPages{}
	}
	var target *scriptmeta.Previous
	operation := "enable"
	if rollback {
		if d.item.Option.VergeScriptPrevious == nil {
			return result, errors.New("no previous script setting is available")
		}
		value := *d.item.Option.VergeScriptPrevious
		if value.Approval != nil {
			copy := *value.Approval
			value.Approval = &copy
		}
		if value.Subscription != nil {
			copy := *value.Subscription
			value.Subscription = &copy
		}
		target = &value
		operation = "rollback"
	} else if update != nil {
		operation = "update-subscription"
	} else if p.Candidate.DataOnlyWithoutArchive {
		operation = "recover-disable"
	} else if !p.Candidate.Selection.Global && !p.Candidate.Selection.Profile {
		operation = "disable"
	}
	a.agentScriptPreviews[id] = vergeScriptPreviewPages{before: p.BeforeRules, after: p.AfterRules, beforeConfig: p.Baseline, afterConfig: p.Effective, bytes: bytes, expires: expires, draft: d, prepared: p, rollback: rollback, rollbackTarget: target, update: update}
	warnings := []string{
		"Preview does not change script settings. Apply the unexpired preview separately.",
		"Scripts use a fixed preview time and deterministic random values; behavior can differ from Clash Verge.",
		"NetFlow preserves managed ports, TUN, mode and controller settings; script changes to them are ignored.",
		"Agent-managed rules are applied after Verge scripts. Existing connections are not rerouted.",
		"The summary shows field names and rules only. Explicitly inspect the full configuration; it may contain credentials.",
	}
	if !d.item.Option.VergeExtensions {
		warnings = append(warnings, "This preview also includes archived Verge data extensions that are currently disabled.")
	}
	if d.target != d.active {
		warnings = append(warnings, "This profile is inactive.")
	}
	if update != nil {
		warnings = append(warnings, "Rollback can restore subscription contents, name, URL and traffic metadata; retained URLs can contain credentials.")
		if update.replacementURL && update.snapshot.URL != d.item.URL {
			warnings = append(warnings, "Applying this preview also replaces the subscription URL.")
		}
	}
	if !d.status.Running {
		warnings = append(warnings, "The core is stopped; applying only saves settings until the core is started.")
	}
	if p.Candidate.DataOnlyWithoutArchive {
		warnings = append(warnings, "The archive is unavailable or invalid; recovery disables both scripts and archived data extensions.")
	}
	if d.baselineUnknown != nil && *d.baselineUnknown {
		warnings = append(warnings, "The previous script output is unavailable; the before view is a data-only estimate and rollback may fail.")
	}
	warnings = append(warnings, p.Validation.Warnings...)
	return agent.VergeScriptPreview{PreviewID: id, Operation: operation, TargetProfile: d.target, ChangedFields: p.Changes.Fields, OtherChangedFields: p.Changes.OtherCount, RulesBefore: before, RulesAfter: after, Warnings: warnings, ExpiresAt: expires}, nil
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

// vergeScriptPreviewConfig is only called for an explicit request. The result
// contains raw private configuration and must never be written to logs.
func (a *App) vergeScriptPreviewConfig(in agent.VergeScriptConfigArgs) (agent.VergeScriptConfigPage, error) {
	p, ok := a.agentScriptPreviews[in.PreviewID]
	if !ok || !p.expires.After(time.Now()) {
		delete(a.agentScriptPreviews, in.PreviewID)
		return agent.VergeScriptConfigPage{}, errors.New("script preview missing or expired")
	}
	var body []byte
	switch in.Stage {
	case "before":
		body = p.beforeConfig
	case "after":
		body = p.afterConfig
	default:
		return agent.VergeScriptConfigPage{}, errors.New("stage must be before or after")
	}
	page, err := scriptpreview.PaginateConfig(body, in.Offset, in.Limit)
	if err != nil {
		return agent.VergeScriptConfigPage{}, err
	}
	return agent.VergeScriptConfigPage{Offset: page.Offset, NextOffset: page.NextOffset, Total: page.Total, Text: page.Text}, nil
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
	if a.tunBusy {
		return d, errors.New("TUN is changing")
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
		if err == nil && d.status.Running {
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
	d.baselineUnknown = new(bool)
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
	if status.Running != d.status.Running || a.tunBusy || a.core.ProfileID() != d.active || a.rewrites.Snapshot().Revision != d.state.Revision || status.TUN != d.status.TUN || status.Mode != d.status.Mode || a.settings.TUN != d.tunSetting || a.chain.Load() != d.chain {
		return scriptpreview.ErrSourcesChanged
	}
	if (a.kernelOptions == nil) != (d.options == nil) || (d.options != nil && !reflect.DeepEqual(a.kernelOptions.Snapshot(), *d.options)) {
		return scriptpreview.ErrSourcesChanged
	}
	if d.target == d.active && d.status.Running {
		current, err := a.core.EffectiveConfig()
		if err != nil || sha256.Sum256(current) != sha256.Sum256(d.activeEffective) {
			return scriptpreview.ErrSourcesChanged
		}
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
func (a *App) vergeScriptBaseline(ctx context.Context, d vergeScriptDraft) ([]byte, []byte, error) {
	var managed, baseline []byte
	var err error
	if d.item.Option.VergeScriptApproval != nil {
		var resolved scriptapproval.Resolved
		resolved, err = scriptapproval.ResolveSnapshotWithRules(ctx, a.dir, *d.item.Option.VergeScriptApproval, d.base, d.item.Name, d.item.Option.VergeArchive, d.item.Option.VergeUID, d.item.Option.VergeRulesBeforeScripts)
		if err == nil {
			managed = resolved.Managed
			baseline, err = profile.RestoreVergeManagedFields(ctx, resolved.Body, managed)
		}
		for path, hash := range resolved.Sources {
			if previous, ok := d.hashes[path]; ok && previous != hash {
				return nil, nil, scriptpreview.ErrSourcesChanged
			}
			d.hashes[path] = hash
		}
	} else {
		var archivePath string
		var archiveHash [32]byte
		managed, archivePath, archiveHash, err = migration.ComposeArchivedWithRules(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, d.base, d.item.Option.VergeRulesBeforeScripts)
		if err == nil {
			d.hashes[archivePath] = archiveHash
		}
		baseline = managed
		if !d.item.Option.VergeExtensions {
			baseline = d.base
		}
	}
	if err != nil && ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if err != nil && d.item.Option.VergeScriptApproval != nil {
		var path string
		var hash [32]byte
		managed, path, hash, err = migration.ComposeArchivedWithRules(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, d.base, d.item.Option.VergeRulesBeforeScripts)
		if err == nil {
			d.hashes[path] = hash
			if d.target == d.active && d.status.Running {
				baseline = d.activeEffective
			} else {
				baseline = d.base
				if d.item.Option.VergeExtensions {
					baseline = managed
				}
				if d.baselineUnknown != nil {
					*d.baselineUnknown = true
				}
			}
		}
	}
	if err != nil {
		return nil, nil, scriptpreview.ErrCandidate
	}
	if d.target == d.active && d.status.Running {
		return d.activeEffective, managed, nil
	}
	baseline, err = d.finalize(baseline)
	if err != nil {
		return nil, nil, scriptpreview.ErrFinalize
	}
	return baseline, managed, nil
}

func (a *App) vergeScriptPreviewInput(d vergeScriptDraft, baseline, managed []byte, selection migration.ScriptSelection, clock time.Time, protect bool) scriptpreview.PrepareInput {
	return scriptpreview.PrepareInput{
		Root: a.dir, Archive: d.item.Option.VergeArchive, UID: d.item.Option.VergeUID, ProfileName: d.item.Name, Base: d.base, Baseline: baseline, Selection: selection, Clock: clock, RulesBeforeScripts: d.item.Option.VergeRulesBeforeScripts,
		Finalize: func(ctx context.Context, body []byte) ([]byte, error) {
			if protect {
				var err error
				body, err = profile.RestoreVergeManagedFields(ctx, body, managed)
				if err != nil {
					return nil, err
				}
			}
			return d.finalize(body)
		},
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
	}
}

func (a *App) prepareVergeScript(ctx context.Context, d vergeScriptDraft, selection migration.ScriptSelection) (scriptpreview.Prepared, error) {
	baseline, managed, err := a.vergeScriptBaseline(ctx, d)
	if err != nil {
		return scriptpreview.Prepared{}, err
	}
	return scriptpreview.Prepare(ctx, a.vergeScriptPreviewInput(d, baseline, managed, selection, d.clock, true))
}
