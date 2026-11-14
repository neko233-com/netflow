// Package scriptapproval stores immutable, content-addressed script outputs.
// Persistence is only a building block: callers must validate the complete
// configuration and recheck all app state before granting approval or reload.
package scriptapproval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptmeta"
	"github.com/neko233-com/netflow/internal/scriptpreview"
	"github.com/neko233-com/netflow/internal/vergescript"
)

var ErrChanged = errors.New("approved script inputs or output changed; preview again")
var ErrCacheFull = errors.New("approved script output storage limit reached; use verge-script-cache-prune")
var cacheMu sync.Mutex

// Approval is metadata only; it does not prove core validation.
type Approval = scriptmeta.Approval

func digest(value [32]byte) string { return hex.EncodeToString(value[:]) }
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(b) == value
}
func cachePath(approval Approval) (string, error) {
	encoded, err := json.Marshal(approval)
	if err != nil {
		return "", ErrChanged
	}
	key := sha256.Sum256(encoded)
	return filepath.Join("verge-script-outputs", digest(key)+".json"), nil
}

// Cache growth is bounded without deleting user files or prior rollback data.
// The app's configuration lock provides cross-process serialization.
func checkCacheLimit(root string, added int) error {
	dir, _, err := safepath.Parent(root, filepath.Join("verge-script-outputs", "placeholder"), true)
	if err != nil {
		return ErrChanged
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return ErrChanged
	}
	entries, readErr := f.ReadDir(129)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return ErrChanged
	}
	if closeErr != nil {
		return ErrChanged
	}
	if len(entries) >= 128 {
		return ErrCacheFull
	}
	total := int64(added)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrChanged
		}
		if info.Size() < 0 || info.Size() > (256<<20)-total {
			return ErrCacheFull
		}
		total += info.Size()
	}
	return nil
}

// Store verifies the candidate and creates an immutable output file, or
// reuses an identical one. The caller is responsible for atomically committing
// the returned metadata only after offline validation and fresh source checks.
// A crash before that commit can leave an unreferenced content-addressed file.
func Store(ctx context.Context, root string, candidate scriptpreview.Candidate, base []byte, name string) (Approval, error) {
	var empty Approval
	if ctx == nil || !candidate.Selection.Global && !candidate.Selection.Profile || len(candidate.Body) == 0 || len(candidate.Body) > vergescript.MaxJSONBytes {
		return empty, ErrChanged
	}
	if err := candidate.CheckCurrent(ctx, root, base, name, candidate.Selection, candidate.Clock); err != nil {
		return empty, cleanError(ctx)
	}
	approval := Approval{Version: 1, Archive: candidate.ArchiveRelative, VergeUID: candidate.VergeUID, Global: candidate.Selection.Global, Profile: candidate.Selection.Profile, RulesBeforeScripts: candidate.RulesBeforeScripts, Clock: candidate.Clock.UTC(), BaseSHA256: digest(candidate.BaseSHA256), NameSHA256: digest(candidate.ProfileNameSHA256), ArchiveSHA256: digest(candidate.ArchiveSHA256), OutputSHA256: digest(candidate.OutputSHA256)}
	path, err := cachePath(approval)
	if err != nil {
		return empty, err
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	existing, readErr := safepath.ReadFileLimit(root, path, vergescript.MaxJSONBytes)
	if readErr == nil {
		if sha256.Sum256(existing) != candidate.OutputSHA256 {
			return empty, ErrChanged
		}
		if err := candidate.CheckCurrent(ctx, root, base, name, candidate.Selection, candidate.Clock); err != nil {
			return empty, cleanError(ctx)
		}
		return approval, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return empty, ErrChanged
	}
	if err := checkCacheLimit(root, len(candidate.Body)); err != nil {
		return empty, err
	}
	created, err := safepath.CreateExclusive(root, path, candidate.Body, true)
	if errors.Is(err, os.ErrExist) {
		body, readErr := safepath.ReadFileLimit(root, path, vergescript.MaxJSONBytes)
		if readErr != nil || sha256.Sum256(body) != candidate.OutputSHA256 {
			return empty, ErrChanged
		}
	} else if err != nil {
		return empty, ErrChanged
	} else {
		defer created.Close()
		written, readErr := safepath.ReadFileLimit(root, path, vergescript.MaxJSONBytes)
		if readErr != nil || sha256.Sum256(written) != candidate.OutputSHA256 {
			_ = created.RemoveIfUnchanged(candidate.Body)
			return empty, cleanError(ctx)
		}
		if err := candidate.CheckCurrent(ctx, root, base, name, candidate.Selection, candidate.Clock); err != nil {
			_ = created.RemoveIfUnchanged(candidate.Body)
			return empty, cleanError(ctx)
		}
	}
	if err := candidate.CheckCurrent(ctx, root, base, name, candidate.Selection, candidate.Clock); err != nil {
		return empty, cleanError(ctx)
	}
	return approval, nil
}

// Resolve rejects changed archive, base, name or output. It never executes JS.
// Runtime users must still apply their own TUN, DNS and Agent rule layers.
func Resolve(ctx context.Context, root string, approval Approval, base []byte, name, archive, uid string) ([]byte, error) {
	result, err := ResolveSnapshot(ctx, root, approval, base, name, archive, uid)
	return result.Body, err
}

// Resolved contains private configuration data and must not be logged.
type Resolved struct {
	Body, Managed []byte
	Sources       map[string][32]byte
	Snapshot      migration.ArchivedScriptSnapshot
}

// ResolveSnapshot returns the data-only composition and exact archive/cache
// hashes from the same archive read, for runtime controls and source checks.
func ResolveSnapshot(ctx context.Context, root string, approval Approval, base []byte, name, archive, uid string) (Resolved, error) {
	return ResolveSnapshotWithRules(ctx, root, approval, base, name, archive, uid, false)
}

func ResolveSnapshotWithRules(ctx context.Context, root string, approval Approval, base []byte, name, archive, uid string, includeRules bool) (Resolved, error) {
	var empty Resolved
	if ctx == nil {
		return empty, ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if approval.Version != 1 || approval.RulesBeforeScripts != includeRules || (!approval.Global && !approval.Profile) || approval.Clock.IsZero() || approval.Archive != archive || approval.VergeUID != uid || len(base) == 0 || len(base) > vergescript.MaxJSONBytes || !validDigest(approval.BaseSHA256) || !validDigest(approval.NameSHA256) || !validDigest(approval.ArchiveSHA256) || !validDigest(approval.OutputSHA256) || approval.BaseSHA256 != digest(sha256.Sum256(base)) || approval.NameSHA256 != digest(sha256.Sum256([]byte(name))) {
		return empty, ErrChanged
	}
	snapshot, extensions, err := migration.ReadArchivedCompositionSelectedWithRules(root, archive, uid, migration.ScriptSelection{Global: approval.Global, Profile: approval.Profile}, includeRules)
	if err != nil || digest(snapshot.ArchiveSHA256) != approval.ArchiveSHA256 || (approval.Global && snapshot.Global == nil) || (approval.Profile && snapshot.Profile == nil) {
		return empty, cleanError(ctx)
	}
	managed, err := profile.ComposeVergeExtensions(base, extensions)
	if err != nil {
		return empty, cleanError(ctx)
	}
	path, err := cachePath(approval)
	if err != nil {
		return empty, cleanError(ctx)
	}
	body, err := safepath.ReadFileLimit(root, path, vergescript.MaxJSONBytes)
	if err != nil || len(body) == 0 || digest(sha256.Sum256(body)) != approval.OutputSHA256 {
		return empty, cleanError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return Resolved{Body: body, Managed: managed, Sources: map[string][32]byte{snapshot.ArchivePath: snapshot.ArchiveSHA256, filepath.Join(root, path): sha256.Sum256(body)}, Snapshot: snapshot}, nil
}

func cleanError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrChanged
}
