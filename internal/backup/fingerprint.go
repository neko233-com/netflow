package backup

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/neko233-com/netflow/internal/safepath"
)

// ManifestFingerprint identifies the contents of a validated running backup,
// independent of ZIP metadata. Entries must be in canonical path order.
func ManifestFingerprint(manifest Manifest) (string, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("netflow-running-snapshot-v1\x00"))
	previous := ""
	var number [8]byte
	for _, entry := range manifest.Files {
		if !validName(entry.Path) || (previous != "" && entry.Path <= previous) || entry.Size < 0 {
			return "", errors.New("invalid snapshot manifest")
		}
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return "", errors.New("invalid snapshot digest")
		}
		binary.BigEndian.PutUint64(number[:], uint64(len(entry.Path)))
		_, _ = h.Write(number[:])
		_, _ = h.Write([]byte(entry.Path))
		binary.BigEndian.PutUint64(number[:], uint64(entry.Size))
		_, _ = h.Write(number[:])
		_, _ = h.Write(digest)
		previous = entry.Path
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RunningInventory cheaply identifies ordinary file additions, removals and
// metadata changes. It is only a hint; callers periodically reconcile using
// RunningFingerprint to detect metadata-preserving edits.
func RunningInventory(ctx context.Context, dir string) (string, error) {
	if ctx == nil || !filepath.IsAbs(dir) {
		return "", errors.New("invalid configuration directory")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rootPath, err := safepath.Canonical(dir)
	if err != nil {
		return "", err
	}
	before, err := scanSources(ctx, rootPath, true)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("netflow-running-inventory-v1\x00"))
	var number [8]byte
	for _, entry := range before {
		binary.BigEndian.PutUint64(number[:], uint64(len(entry.rel)))
		_, _ = h.Write(number[:])
		_, _ = h.Write([]byte(entry.rel))
		binary.BigEndian.PutUint64(number[:], uint64(entry.info.Size()))
		_, _ = h.Write(number[:])
		binary.BigEndian.PutUint64(number[:], uint64(entry.info.ModTime().UnixNano()))
		_, _ = h.Write(number[:])
	}
	after, err := scanSources(ctx, rootPath, true)
	if err != nil {
		return "", err
	}
	if !sameSources(before, after) {
		return "", errors.New("configuration changed during inventory")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RunningFingerprint hashes every included file twice and checks the file set
// before and after. It does not create an archive or mutate the configuration.
func RunningFingerprint(ctx context.Context, dir string) (string, error) {
	if ctx == nil || !filepath.IsAbs(dir) {
		return "", errors.New("invalid configuration directory")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rootPath, err := safepath.Canonical(dir)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	sources, err := scanSources(ctx, rootPath, true)
	if err != nil {
		return "", err
	}
	entries := make([]Entry, 0, len(sources))
	for _, item := range sources {
		f, err := root.Open(filepath.FromSlash(item.rel))
		if err != nil {
			return "", err
		}
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() || !os.SameFile(item.info, info) {
			f.Close()
			return "", errors.New("configuration changed during fingerprint")
		}
		h := sha256.New()
		n, readErr := io.Copy(h, contextReader{ctx, io.LimitReader(f, maxFileBytes+1)})
		after, afterErr := f.Stat()
		closeErr := f.Close()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if readErr != nil || afterErr != nil || closeErr != nil || n != item.info.Size() || after.Size() != item.info.Size() || !after.ModTime().Equal(item.info.ModTime()) {
			return "", errors.New("configuration changed during fingerprint")
		}
		entries = append(entries, Entry{Path: item.rel, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	if err := verifySourceHashes(ctx, root, sources, entries); err != nil {
		return "", err
	}
	after, err := scanSources(ctx, rootPath, true)
	if err != nil {
		return "", err
	}
	if !sameSources(sources, after) {
		return "", errors.New("configuration changed during fingerprint")
	}
	result, err := ManifestFingerprint(Manifest{Files: entries})
	if err != nil {
		return "", fmt.Errorf("fingerprint: %w", err)
	}
	return result, nil
}
