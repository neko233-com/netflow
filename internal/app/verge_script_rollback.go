package app

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptmeta"
	"github.com/neko233-com/netflow/internal/scriptpreview"
)

// prepareVergeScriptDisable normally retains data extensions. If the archive
// is unreadable or invalid, it previews a recovery that disables both scripts
// and extensions and uses only the raw subscription as its configuration.
func (a *App) prepareVergeScriptDisable(ctx context.Context, d vergeScriptDraft) (scriptpreview.Prepared, error) {
	var empty scriptpreview.Prepared
	if ctx == nil {
		return empty, errors.New("context is required")
	}
	if d.item.Option.VergeScriptApproval == nil {
		return empty, errors.New("scripts are already disabled")
	}
	_, ext, archiveErr := migration.ReadArchivedCompositionSelected(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, migration.ScriptSelection{})
	if archiveErr == nil {
		_, archiveErr = profile.ComposeVergeExtensions(d.base, ext)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if archiveErr == nil {
		disable := d
		disable.item.Option.VergeScriptPrevious = &scriptmeta.Previous{VergeExtensions: d.item.Option.VergeExtensions}
		return a.prepareVergeScriptRollback(ctx, disable)
	}
	baseline := d.activeEffective
	if d.target != d.active || !d.status.Running {
		var err error
		baseline, err = d.finalize(d.base)
		if err != nil {
			return empty, scriptpreview.ErrFinalize
		}
		if d.baselineUnknown != nil {
			*d.baselineUnknown = true
		}
	}
	candidate := scriptpreview.Candidate{Body: append([]byte(nil), d.base...), BaseSHA256: sha256.Sum256(d.base), ProfileNameSHA256: sha256.Sum256([]byte(d.item.Name)), OutputSHA256: sha256.Sum256(d.base), ArchiveRelative: d.item.Option.VergeArchive, VergeUID: d.item.Option.VergeUID, Clock: d.clock, DataOnlyWithoutArchive: true}
	return scriptpreview.PrepareCandidate(ctx, a.vergeScriptPreviewInput(d, baseline, nil, migration.ScriptSelection{}, d.clock, false), candidate)
}

// prepareVergeScriptRollback validates the exact previous output; it never
// reruns JavaScript. A data-only previous state may contain no extensions.
func (a *App) prepareVergeScriptRollback(ctx context.Context, d vergeScriptDraft) (scriptpreview.Prepared, error) {
	var empty scriptpreview.Prepared
	if ctx == nil {
		return empty, errors.New("context is required")
	}
	previous := d.item.Option.VergeScriptPrevious
	if previous == nil {
		return empty, errors.New("no previous script setting is available")
	}
	baseline, _, err := a.vergeScriptBaseline(ctx, d)
	if err != nil {
		return empty, err
	}
	next := d
	update, err := a.rollbackSubscription(d)
	if err != nil {
		return empty, err
	}
	if update != nil {
		next.base = profile.EnsureMixedPort(update.body, 7897)
		if update.snapshot.Name != "" {
			next.item.Name = update.snapshot.Name
		}
	}
	selection := migration.ScriptSelection{}
	clock := d.clock
	var snapshot migration.ArchivedScriptSnapshot
	var body, managed []byte
	protect := previous.Approval != nil
	if protect {
		approval := *previous.Approval
		selection = migration.ScriptSelection{Global: approval.Global, Profile: approval.Profile}
		clock = approval.Clock
		resolved, err := scriptapproval.ResolveSnapshot(ctx, a.dir, approval, next.base, next.item.Name, d.item.Option.VergeArchive, d.item.Option.VergeUID)
		if err != nil {
			return empty, scriptpreview.ErrSourcesChanged
		}
		snapshot, body, managed = resolved.Snapshot, resolved.Body, resolved.Managed
		for path, hash := range resolved.Sources {
			if current, ok := d.hashes[path]; ok && current != hash {
				return empty, scriptpreview.ErrSourcesChanged
			}
			d.hashes[path] = hash
		}
	} else {
		var ext profile.VergeExtensions
		snapshot, ext, err = migration.ReadArchivedCompositionSelected(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, selection)
		if err != nil {
			return empty, scriptpreview.ErrCandidate
		}
		body = next.base
		if previous.VergeExtensions {
			body, err = profile.ComposeVergeExtensions(next.base, ext)
			if err != nil {
				return empty, scriptpreview.ErrCandidate
			}
		}
		if current, ok := d.hashes[snapshot.ArchivePath]; ok && current != snapshot.ArchiveSHA256 {
			return empty, scriptpreview.ErrSourcesChanged
		}
		d.hashes[snapshot.ArchivePath] = snapshot.ArchiveSHA256
	}
	candidate := scriptpreview.Candidate{Body: append([]byte(nil), body...), BaseSHA256: sha256.Sum256(next.base), ArchiveSHA256: snapshot.ArchiveSHA256, ArchivePath: snapshot.ArchivePath, ArchiveRelative: d.item.Option.VergeArchive, VergeUID: d.item.Option.VergeUID, ProfileNameSHA256: sha256.Sum256([]byte(next.item.Name)), OutputSHA256: sha256.Sum256(body), Clock: clock, Selection: selection}
	if selection.Global {
		if snapshot.Global == nil {
			return empty, scriptpreview.ErrSourcesChanged
		}
		candidate.Steps = append(candidate.Steps, scriptpreview.Step{Scope: "global", ScriptSHA256: snapshot.Global.SHA256})
	}
	if selection.Profile {
		if snapshot.Profile == nil {
			return empty, scriptpreview.ErrSourcesChanged
		}
		candidate.Steps = append(candidate.Steps, scriptpreview.Step{Scope: "profile", ScriptSHA256: snapshot.Profile.SHA256})
	}
	return scriptpreview.PrepareCandidate(ctx, a.vergeScriptPreviewInput(next, baseline, managed, selection, clock, protect), candidate)
}
