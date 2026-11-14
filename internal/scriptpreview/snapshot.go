// Package scriptpreview builds reproducible, read-only candidates. Callers
// must validate the complete core configuration and recheck every source and
// runtime state before applying anything.
package scriptpreview

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/vergescript"
)

type Step struct {
	Scope        string
	InputSHA256  [32]byte
	ScriptSHA256 [32]byte
	OutputSHA256 [32]byte
}
type Candidate struct {
	// Body can contain subscription credentials and must not be logged.
	Body              []byte
	BaseSHA256        [32]byte
	ArchiveSHA256     [32]byte
	ArchivePath       string
	ArchiveRelative   string
	VergeUID          string
	ProfileNameSHA256 [32]byte
	OutputSHA256      [32]byte
	Clock             time.Time
	Selection         migration.ScriptSelection
	Steps             []Step
}

// Build reads one archive snapshot, applies selected scripts with a fixed
// clock and runs each script twice to detect unstable output. A candidate is
// not permission to apply and is not proof of core validation. Base must
// already contain the rule layers that precede Verge scripts.
func Build(ctx context.Context, root, relative, uid string, base []byte, profileName string, selection migration.ScriptSelection, clock time.Time) (Candidate, error) {
	var empty Candidate
	if ctx == nil || clock.IsZero() || len(base) == 0 || len(base) > vergescript.MaxJSONBytes {
		return empty, errors.New("invalid script preview input")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	snapshot, extensions, err := migration.ReadArchivedCompositionSelected(root, relative, uid, selection)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	type expected struct {
		scope string
		hash  [32]byte
	}
	var want []expected
	if selection.Global {
		if snapshot.Global == nil {
			return empty, errors.New("global script is unavailable")
		}
		want = append(want, expected{"global", snapshot.Global.SHA256})
	}
	if selection.Profile {
		if snapshot.Profile == nil {
			return empty, errors.New("profile script is unavailable")
		}
		want = append(want, expected{"profile", snapshot.Profile.SHA256})
	}
	steps := make([]Step, 0, len(want))
	execute := func(ctx context.Context, input []byte, source, name string) ([]byte, error) {
		if len(steps) >= len(want) {
			return nil, errors.New("unexpected script stage")
		}
		result, err := vergescript.CheckYAMLAt(ctx, input, source, name, clock)
		if err != nil {
			return nil, err
		}
		expected := want[len(steps)]
		if result.ScriptSHA256 != expected.hash {
			return nil, errors.New("script snapshot changed")
		}
		steps = append(steps, Step{Scope: expected.scope, InputSHA256: result.InputSHA256, ScriptSHA256: result.ScriptSHA256, OutputSHA256: result.OutputSHA256})
		return result.Body, nil
	}
	output, err := migration.ComposeArchivedSnapshot(ctx, base, snapshot, extensions, profileName, selection, execute)
	if err != nil {
		return empty, err
	}
	if len(output) > vergescript.MaxJSONBytes || len(steps) != len(want) {
		return empty, errors.New("script preview output is too large or incomplete")
	}
	result := Candidate{Body: append([]byte(nil), output...), BaseSHA256: sha256.Sum256(base), ArchiveSHA256: snapshot.ArchiveSHA256, ArchivePath: snapshot.ArchivePath, ArchiveRelative: relative, VergeUID: uid, ProfileNameSHA256: sha256.Sum256([]byte(profileName)), OutputSHA256: sha256.Sum256(output), Clock: clock.UTC(), Selection: selection, Steps: steps}
	if err := result.CheckCurrent(ctx, root, base, profileName, selection, clock); err != nil {
		return empty, err
	}
	return result, nil
}

// CheckCurrent rechecks only the inputs bound by Candidate. The app must also
// check the profile catalog, rule revision, kernel options, TUN and provider
// snapshots immediately before applying any proposal.
func (c Candidate) CheckCurrent(ctx context.Context, root string, base []byte, profileName string, selection migration.ScriptSelection, clock time.Time) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Clock.IsZero() || !c.Clock.Equal(clock) || c.Selection != selection || c.BaseSHA256 != sha256.Sum256(base) || c.ProfileNameSHA256 != sha256.Sum256([]byte(profileName)) || c.OutputSHA256 != sha256.Sum256(c.Body) {
		return errors.New("script preview changed; preview again")
	}
	snapshot, _, err := migration.ReadArchivedCompositionSelected(root, c.ArchiveRelative, c.VergeUID, selection)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err != nil || snapshot.ArchiveSHA256 != c.ArchiveSHA256 || snapshot.ArchivePath != c.ArchivePath {
		return errors.New("script archive changed; preview again")
	}
	index := 0
	if selection.Global {
		if snapshot.Global == nil || index >= len(c.Steps) || c.Steps[index].Scope != "global" || c.Steps[index].ScriptSHA256 != snapshot.Global.SHA256 {
			return errors.New("global script changed; preview again")
		}
		index++
	}
	if selection.Profile {
		if snapshot.Profile == nil || index >= len(c.Steps) || c.Steps[index].Scope != "profile" || c.Steps[index].ScriptSHA256 != snapshot.Profile.SHA256 {
			return errors.New("profile script changed; preview again")
		}
		index++
	}
	if index != len(c.Steps) {
		return errors.New("script preview changed; preview again")
	}
	return nil
}
