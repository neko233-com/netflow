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

// Kernel errors may include subscription URLs or credentials. Preserve
// cancellation semantics without returning arbitrary kernel diagnostics.
func vergeApplyCause(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("script application failed")
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

// beginVergeScriptCommit runs on the app event loop and stages the validated
// catalog change. Its transaction restores the previous snapshot on failure.
func (a *App) beginVergeScriptCommit(ctx context.Context, ready vergeScriptCommit) (bool, *guiConfigTransaction, error) {
	if ctx == nil {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if err := ctx.Err(); err != nil {
		return false, nil, err
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
		return false, nil, errors.New("script preview expired; preview again")
	}
	if err := a.checkVergeScriptDraft(d); err != nil {
		return false, nil, err
	}
	for path, hash := range ready.sources {
		if existing, ok := d.hashes[path]; ok && existing != hash {
			return false, nil, scriptpreview.ErrSourcesChanged
		}
		d.hashes[path] = hash
	}
	if err := a.checkAgentSources(d.hashes); err != nil {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if err := p.Candidate.CheckCurrent(ctx, a.dir, candidateBase, candidateName, p.Candidate.Selection, p.Candidate.Clock); err != nil {
		if ctx.Err() != nil {
			return false, nil, ctx.Err()
		}
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	catalog, snapshot, err := a.profiles.LoadForUpdate()
	if err != nil || sha256.Sum256(snapshot) != d.hashes[filepath.Join(a.dir, "profiles.json")] {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	index := -1
	for i := range catalog.Items {
		if catalog.Items[i].UID == d.target {
			index = i
			break
		}
	}
	if index < 0 {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if ready.proposal.update != nil {
		return a.beginVergeSubscriptionUpdate(ctx, ready, catalog, snapshot, index, candidateBase)
	}
	option := &catalog.Items[index].Option
	previous := &scriptmeta.Previous{VergeExtensions: option.VergeExtensions}
	if option.VergeScriptApproval != nil {
		value := *option.VergeScriptApproval
		previous.Approval = &value
	}
	option.VergeScriptPrevious, option.VergeScriptApproval, option.VergeExtensions = previous, ready.approval, ready.extensions
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	if err := a.profiles.SaveIfUnchanged(catalog, snapshot); err != nil {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	active := d.status.Running && d.target == d.active
	return active, &guiConfigTransaction{
		reload: active,
		commit: func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if active {
				effective, err := a.core.EffectiveConfig()
				if err != nil || sha256.Sum256(effective) != p.EffectiveSHA256 {
					return errors.New("script apply did not match preview")
				}
			}
			return nil
		},
		rollback: func() (bool, error) {
			if err := a.profiles.RestoreSnapshotIfUnchanged(catalog, snapshot); err != nil {
				return false, errors.New("script apply failed; restoring catalog failed, inspect configuration")
			}
			return active, nil
		},
		wrap: func(cause, restoreErr error) error {
			if restoreErr != nil {
				return errors.Join(vergeApplyCause(cause), errors.New("script apply failed; restoration failed, inspect configuration"))
			}
			return errors.Join(vergeApplyCause(cause), errors.New("script apply failed; previous configuration restored"))
		},
	}, nil
}

// The headless path uses the same staging and rollback rules synchronously.
func (a *App) finishVergeScriptCommit(ctx context.Context, ready vergeScriptCommit) (bool, error) {
	active, tx, err := a.beginVergeScriptCommit(ctx, ready)
	if err != nil {
		return false, err
	}
	if tx.reload {
		err = a.core.Reload()
	}
	if err == nil {
		err = tx.commit()
	}
	if err == nil {
		return active, nil
	}
	needReload, restoreErr := tx.rollback()
	if restoreErr == nil && needReload {
		restoreErr = a.core.Reload()
	}
	return false, tx.wrap(err, restoreErr)
}
