package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptmeta"
	"github.com/neko233-com/netflow/internal/scriptpreview"
)

// vergeSubscriptionUpdate is private preview state; body can contain tokens.
// A nonempty snapshot path means rollback to an existing retained file.
type vergeSubscriptionUpdate struct {
	body           []byte
	snapshot       scriptmeta.SubscriptionSnapshot
	replacementURL bool
}

// rollbackSubscription binds both the current and retained files to a
// rollback draft. The returned bytes stay private to the preview.
func (a *App) rollbackSubscription(d vergeScriptDraft) (*vergeSubscriptionUpdate, error) {
	previous := d.item.Option.VergeScriptPrevious
	if previous == nil || previous.Subscription == nil {
		return nil, nil
	}
	current, currentPath, err := readProfileFile(a.dir, d.item.File)
	if err != nil {
		return nil, scriptpreview.ErrSourcesChanged
	}
	currentHash := sha256.Sum256(current)
	if old, ok := d.hashes[currentPath]; ok && old != currentHash {
		return nil, scriptpreview.ErrSourcesChanged
	}
	d.hashes[currentPath] = currentHash
	if d.target == d.active && !bytes.Equal(profile.EnsureMixedPort(current, 7897), d.base) {
		return nil, scriptpreview.ErrSourcesChanged
	}
	retained, retainedPath, err := readProfileFile(a.dir, previous.Subscription.File)
	if err != nil {
		return nil, scriptpreview.ErrSourcesChanged
	}
	retainedHash := sha256.Sum256(retained)
	if old, ok := d.hashes[retainedPath]; ok && old != retainedHash {
		return nil, scriptpreview.ErrSourcesChanged
	}
	d.hashes[retainedPath] = retainedHash
	snapshot := *previous.Subscription
	return &vergeSubscriptionUpdate{body: retained, snapshot: snapshot}, nil
}

// beginVergeSubscriptionUpdate runs on the event loop. New subscription
// bytes are written to a unique file before the catalog atomically switches
// both file and script approval. Startup rebuilds config.yaml from the catalog
// if the process stops between the catalog and active-config writes.
func (a *App) beginVergeSubscriptionUpdate(ctx context.Context, ready vergeScriptCommit, catalog profile.File, catalogBefore []byte, index int, nextBase []byte) (bool, *guiConfigTransaction, error) {
	d, p, update := ready.proposal.draft, ready.proposal.prepared, ready.proposal.update
	if update == nil || index < 0 || index >= len(catalog.Items) || catalog.Items[index].UID != d.target {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	item := &catalog.Items[index]
	nextURL := update.snapshot.URL
	if nextURL == "" {
		// Snapshots created by 0.2.91 did not record the unchanged URL.
		nextURL = item.URL
	}
	if (item.Type == "remote" && !profile.ValidURL(nextURL)) || (item.Type != "remote" && nextURL != "") || (update.snapshot.File == "" && nextURL != item.URL && !update.replacementURL) {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	nextName := update.snapshot.Name
	if nextName == "" {
		nextName = item.Name
	}
	if len(nextName) > 256 || strings.ContainsAny(nextName, "\r\n\x00") || (update.snapshot.File == "" && nextName != item.Name) {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	oldBody, oldPath, err := readProfileFile(a.dir, item.File)
	if err != nil || d.hashes[oldPath] != sha256.Sum256(oldBody) {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if d.target == d.active && !bytes.Equal(profile.EnsureMixedPort(oldBody, 7897), d.base) {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	nextFile := update.snapshot.File
	if nextFile == "" {
		nextFile = ready.stagedFile
	}
	if nextFile == "" {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	retained, path, readErr := readProfileFile(a.dir, nextFile)
	retainedHash := sha256.Sum256(retained)
	if readErr != nil || !bytes.Equal(retained, update.body) {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if previous, ok := d.hashes[path]; ok && previous != retainedHash {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if update.snapshot.File != "" {
		if _, ok := d.hashes[path]; !ok {
			return false, nil, scriptpreview.ErrSourcesChanged
		}
	}
	d.hashes[path] = retainedHash
	previous := &scriptmeta.Previous{VergeExtensions: item.Option.VergeExtensions, Subscription: &scriptmeta.SubscriptionSnapshot{File: item.File, URL: item.URL, Name: item.Name, Updated: item.Updated, Used: item.Used, Total: item.Total, Expire: item.Expire}}
	if item.Option.VergeScriptApproval != nil {
		copy := *item.Option.VergeScriptApproval
		previous.Approval = &copy
	}
	item.File, item.URL, item.Name, item.Updated, item.Used, item.Total, item.Expire = nextFile, nextURL, nextName, update.snapshot.Updated, update.snapshot.Used, update.snapshot.Total, update.snapshot.Expire
	item.Option.VergeScriptPrevious, item.Option.VergeScriptApproval, item.Option.VergeExtensions = previous, ready.approval, ready.extensions
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	if err := a.checkAgentSources(d.hashes); err != nil {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	if err := a.profiles.SaveIfUnchanged(catalog, catalogBefore); err != nil {
		return false, nil, scriptpreview.ErrSourcesChanged
	}
	active := d.target == d.active
	if active {
		if err := safepath.CompareAndWrite(a.dir, "config.yaml", d.base, nextBase); err != nil {
			if restoreErr := a.profiles.RestoreSnapshotIfUnchanged(catalog, catalogBefore); restoreErr != nil {
				return false, nil, errors.Join(err, errors.New("subscription update failed and catalog changed; inspect configuration"))
			}
			return false, nil, err
		}
	}
	running := active && d.status.Running
	return running, &guiConfigTransaction{
		reload: running,
		commit: func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if running {
				effective, err := a.core.EffectiveConfig()
				if err != nil || sha256.Sum256(effective) != p.EffectiveSHA256 {
					return errors.New("subscription update did not match preview")
				}
			}
			delete(a.profileAutoReview, d.target)
			delete(a.profileAutoRetry, d.target)
			return nil
		},
		rollback: func() (bool, error) {
			if err := a.profiles.RestoreSnapshotIfUnchanged(catalog, catalogBefore); err != nil {
				return false, errors.New("subscription update failed and catalog changed; inspect configuration")
			}
			if active {
				if err := safepath.CompareAndWrite(a.dir, "config.yaml", nextBase, d.base); err != nil {
					return false, fmt.Errorf("subscription update failed and active config could not be restored: %w", err)
				}
			}
			return running, nil
		},
		wrap: func(cause, restoreErr error) error {
			if restoreErr != nil {
				return errors.Join(vergeApplyCause(cause), errors.New("subscription update restoration failed; inspect configuration"))
			}
			return vergeApplyCause(cause)
		},
	}, nil
}

// prepareVergeScriptUpdate compares the current approved configuration with
// the downloaded subscription after running the same selected scripts. It
// performs no writes: its caller must retain the returned candidate and
// separately commit the subscription and approval after explicit review.
// Both the existing profile file and active configuration are bound to the
// draft, so an external edit during download invalidates the preview.
func (a *App) prepareVergeScriptUpdate(ctx context.Context, d vergeScriptDraft, source profileSourceSnapshot, downloaded []byte) (scriptpreview.Prepared, error) {
	var empty scriptpreview.Prepared
	approval := d.item.Option.VergeScriptApproval
	if approval == nil || (!approval.Global && !approval.Profile) {
		return empty, errors.New("profile has no approved scripts")
	}
	if err := validateProfileShape(downloaded); err != nil {
		return empty, scriptpreview.ErrCandidate
	}
	old, path, err := readProfileFile(a.dir, d.item.File)
	if err != nil {
		return empty, scriptpreview.ErrSourcesChanged
	}
	oldHash := sha256.Sum256(old)
	if source.file != d.item.File || source.hash != oldHash {
		return empty, scriptpreview.ErrSourcesChanged
	}
	if previous, ok := d.hashes[path]; ok && previous != oldHash {
		return empty, scriptpreview.ErrSourcesChanged
	}
	d.hashes[path] = oldHash
	if d.target == d.active && !bytes.Equal(profile.EnsureMixedPort(old, 7897), d.base) {
		return empty, scriptpreview.ErrSourcesChanged
	}
	baseline, _, err := a.vergeScriptBaseline(ctx, d)
	if err != nil {
		return empty, err
	}
	next := d
	next.base = profile.EnsureMixedPort(downloaded, 7897)
	managed, archivePath, archiveHash, err := migration.ComposeArchivedWithRules(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, next.base, d.item.Option.VergeRulesBeforeScripts)
	if err != nil {
		return empty, scriptpreview.ErrCandidate
	}
	if previous, ok := d.hashes[archivePath]; ok && previous != archiveHash {
		return empty, scriptpreview.ErrSourcesChanged
	}
	d.hashes[archivePath] = archiveHash
	selection := migration.ScriptSelection{Global: approval.Global, Profile: approval.Profile}
	return scriptpreview.Prepare(ctx, a.vergeScriptPreviewInput(next, baseline, managed, selection, d.clock, true))
}
