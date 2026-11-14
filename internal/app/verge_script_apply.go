package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptmeta"
	"github.com/neko233-com/netflow/internal/scriptpreview"
)

type vergeScriptCommit struct {
	proposal   vergeScriptPreviewPages
	approval   *scriptmeta.Approval
	extensions bool
	sources    map[string][32]byte
	stagedFile string
}

// prepareVergeScriptCommit may run off the app event loop. It writes only an
// immutable output file; it does not commit any setting or reload the kernel.
func (a *App) prepareVergeScriptCommit(ctx context.Context, proposal vergeScriptPreviewPages) (vergeScriptCommit, error) {
	var empty vergeScriptCommit
	if ctx == nil || !proposal.expires.After(time.Now()) {
		return empty, errors.New("script preview missing or expired")
	}
	d, p := proposal.draft, proposal.prepared
	candidateBase := d.base
	candidateName := d.item.Name
	if proposal.update != nil {
		candidateBase = profile.EnsureMixedPort(proposal.update.body, 7897)
		if proposal.update.snapshot.Name != "" {
			candidateName = proposal.update.snapshot.Name
		}
	}
	if sha256.Sum256(p.Effective) != p.EffectiveSHA256 || (d.status.Running && d.target == d.active && sha256.Sum256(p.Baseline) != sha256.Sum256(d.activeEffective)) {
		return empty, scriptpreview.ErrSourcesChanged
	}
	if err := p.Candidate.CheckCurrent(ctx, a.dir, candidateBase, candidateName, p.Candidate.Selection, p.Candidate.Clock); err != nil {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		return empty, scriptpreview.ErrSourcesChanged
	}
	if err := a.checkAgentSources(d.hashes); err != nil {
		return empty, scriptpreview.ErrSourcesChanged
	}
	var approval *scriptmeta.Approval
	extensions := true
	if proposal.rollback {
		if proposal.rollbackTarget == nil {
			return empty, scriptpreview.ErrSourcesChanged
		}
		extensions = proposal.rollbackTarget.VergeExtensions
		if proposal.rollbackTarget.Approval != nil {
			value := *proposal.rollbackTarget.Approval
			approval = &value
		}
	} else if !p.Candidate.Selection.Global && !p.Candidate.Selection.Profile {
		extensions = d.item.Option.VergeExtensions
		if p.Candidate.DataOnlyWithoutArchive {
			extensions = false
		}
	} else {
		value, err := scriptapproval.Store(ctx, a.dir, p.Candidate, candidateBase, candidateName)
		if err != nil {
			return empty, err
		}
		approval = &value
	}
	var body []byte
	var sources map[string][32]byte
	var err error
	if approval != nil {
		resolved, resolveErr := scriptapproval.ResolveSnapshotWithRules(ctx, a.dir, *approval, candidateBase, candidateName, d.item.Option.VergeArchive, d.item.Option.VergeUID, d.item.Option.VergeRulesBeforeScripts)
		if resolveErr != nil || !bytes.Equal(resolved.Body, p.Candidate.Body) {
			return empty, scriptpreview.ErrSourcesChanged
		}
		sources = resolved.Sources
		body, err = profile.RestoreVergeManagedFields(ctx, resolved.Body, resolved.Managed)
	} else {
		body = append([]byte(nil), p.Candidate.Body...)
	}
	if err == nil {
		body, err = d.finalize(body)
	}
	if err != nil || sha256.Sum256(body) != p.EffectiveSHA256 {
		return empty, scriptpreview.ErrSourcesChanged
	}
	for path, hash := range sources {
		if existing, ok := d.hashes[path]; ok && existing != hash {
			return empty, scriptpreview.ErrSourcesChanged
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var stagedFile string
	if proposal.update != nil && proposal.update.snapshot.File == "" {
		stagedFile, err = scriptapproval.StoreSubscription(ctx, a.dir, proposal.update.body)
		if err != nil {
			return empty, err
		}
	}
	return vergeScriptCommit{proposal: proposal, approval: approval, extensions: extensions, sources: sources, stagedFile: stagedFile}, nil
}

// finishVergeScriptCommit is serialized on the app event loop. It commits
// the catalog conditionally, reloads the active profile and restores the exact
// previous catalog on failure. The caller must preview rollback separately.
func (a *App) finishVergeScriptCommit(ctx context.Context, ready vergeScriptCommit) (bool, error) {
	if ctx == nil {
		return false, scriptpreview.ErrSourcesChanged
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p, d := ready.proposal.prepared, ready.proposal.draft
	candidateBase := d.base
	candidateName := d.item.Name
	if ready.proposal.update != nil {
		candidateBase = profile.EnsureMixedPort(ready.proposal.update.body, 7897)
		if ready.proposal.update.snapshot.Name != "" {
			candidateName = ready.proposal.update.snapshot.Name
		}
	}
	if !ready.proposal.expires.After(time.Now()) {
		return false, errors.New("script preview expired; preview again")
	}
	if err := a.checkVergeScriptDraft(d); err != nil {
		return false, err
	}
	for path, hash := range ready.sources {
		if existing, ok := d.hashes[path]; ok && existing != hash {
			return false, scriptpreview.ErrSourcesChanged
		}
		d.hashes[path] = hash
	}
	if err := a.checkAgentSources(d.hashes); err != nil {
		return false, scriptpreview.ErrSourcesChanged
	}
	if err := p.Candidate.CheckCurrent(ctx, a.dir, candidateBase, candidateName, p.Candidate.Selection, p.Candidate.Clock); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, scriptpreview.ErrSourcesChanged
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil || sha256.Sum256(snapshot) != d.hashes[filepath.Join(a.dir, "profiles.json")] {
		return false, scriptpreview.ErrSourcesChanged
	}
	index := -1
	for i := range catalog.Items {
		if catalog.Items[i].UID == d.target {
			index = i
			break
		}
	}
	if index < 0 {
		return false, scriptpreview.ErrSourcesChanged
	}
	if ready.proposal.update != nil {
		return a.finishVergeSubscriptionUpdate(ctx, ready, catalog, snapshot, index, candidateBase)
	}
	option := &catalog.Items[index].Option
	previous := &scriptmeta.Previous{VergeExtensions: option.VergeExtensions}
	if option.VergeScriptApproval != nil {
		value := *option.VergeScriptApproval
		previous.Approval = &value
	}
	option.VergeScriptPrevious, option.VergeScriptApproval, option.VergeExtensions = previous, ready.approval, ready.extensions
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		return false, scriptpreview.ErrSourcesChanged
	}
	active := d.status.Running && d.target == d.active
	if !active {
		return false, nil
	}
	rollback := func() error {
		if err := a.profiles.RestoreSnapshotIfUnchanged(catalog, snapshot); err != nil {
			return errors.New("script apply failed; restoring catalog failed, inspect configuration")
		}
		if err := a.core.Reload(); err != nil {
			return errors.New("script apply failed; restoring running core failed, inspect configuration")
		}
		return errors.New("script apply failed; previous configuration restored")
	}
	if err := a.core.Reload(); err != nil {
		return false, rollback()
	}
	effective, err := a.core.EffectiveConfig()
	if err != nil || sha256.Sum256(effective) != p.EffectiveSHA256 {
		return false, rollback()
	}
	return true, nil
}
