package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/scriptpreview"
)

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
	if err := validateProfile(downloaded); err != nil {
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
	managed, archivePath, archiveHash, err := migration.ComposeArchived(a.dir, d.item.Option.VergeArchive, d.item.Option.VergeUID, next.base)
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
