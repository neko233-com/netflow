package scriptapproval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/safepath"
)

const subscriptionDir = "profiles/.netflow-script-subscriptions"
const maxSubscriptionFiles = 128
const maxSubscriptionTotal = 256 << 20
const maxSubscriptionBytes = 8 << 20

var ErrSubscriptionCacheFull = errors.New("retained subscription storage limit reached; use verge-script-cache-prune")

// StoreSubscription retains private subscription bytes before a reviewed
// catalog transaction. It must run off the UI thread. Unreferenced files
// left by failed or interrupted commits can be removed with PruneSubscriptions.
func StoreSubscription(ctx context.Context, root string, body []byte) (string, error) {
	if ctx == nil || len(body) == 0 || len(body) > maxSubscriptionBytes {
		return "", ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	dir, _, err := safepath.Parent(root, filepath.Join(subscriptionDir, "placeholder"), true)
	if err != nil {
		return "", ErrChanged
	}
	f, err := dir.Open(".")
	if err != nil {
		_ = dir.Close()
		return "", ErrChanged
	}
	entries, readErr := f.ReadDir(maxSubscriptionFiles + 1)
	closeErr, rootErr := f.Close(), dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || rootErr != nil {
		return "", ErrChanged
	}
	if len(entries) >= maxSubscriptionFiles {
		return "", ErrSubscriptionCacheFull
	}
	total := int64(len(body))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return "", ErrChanged
		}
		if info.Size() < 0 || info.Size() > maxSubscriptionTotal-total {
			return "", ErrSubscriptionCacheFull
		}
		total += info.Size()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	rel := filepath.Join(subscriptionDir, "netflow-"+hex.EncodeToString(nonce[:])+".yaml")
	created, err := safepath.CreateExclusive(root, rel, body, false)
	if err != nil {
		return "", err
	}
	if err := created.Close(); err != nil {
		return "", err
	}
	return rel, nil
}

func managedSubscriptionName(name string) bool {
	if len(name) != len("netflow-")+32+len(".yaml") || !strings.HasPrefix(name, "netflow-") || !strings.HasSuffix(name, ".yaml") {
		return false
	}
	part := strings.TrimSuffix(strings.TrimPrefix(name, "netflow-"), ".yaml")
	decoded, err := hex.DecodeString(part)
	return err == nil && hex.EncodeToString(decoded) == part
}

// PruneSubscriptions removes only NetFlow-named files that are not in refs.
// Guard rechecks the catalog before each removal. As with cache pruning, an
// external process can still race the final check and filesystem operation.
func PruneSubscriptions(ctx context.Context, root string, refs []string, guard func() error) (PruneResult, error) {
	var result PruneResult
	if ctx == nil || guard == nil {
		return result, errors.New("subscription cleanup is not configured")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if len(refs) > 10000 {
		return result, ErrChanged
	}
	kept := map[string]bool{}
	for _, ref := range refs {
		if strings.EqualFold(filepath.Clean(filepath.Dir(ref)), filepath.Clean(filepath.FromSlash(subscriptionDir))) {
			kept[strings.ToLower(filepath.Base(ref))] = true
		}
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	dir, _, err := safepath.Parent(root, filepath.Join(subscriptionDir, "placeholder"), false)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, ErrChanged
	}
	f, err := dir.Open(".")
	if err != nil {
		_ = dir.Close()
		return result, ErrChanged
	}
	entries, readErr := f.ReadDir(4097)
	closeErr, rootErr := f.Close(), dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || rootErr != nil || len(entries) > 4096 {
		return result, ErrChanged
	}
	// A reference may use a hard link or a Windows short-name alias rather
	// than the canonical cache name. Preserve the underlying file as well.
	var referenced []os.FileInfo
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		f, err := safepath.OpenRead(root, ref)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return result, ErrChanged
		}
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
			return result, ErrChanged
		}
		referenced = append(referenced, info)
	}
	for _, entry := range entries {
		name := entry.Name()
		if kept[strings.ToLower(name)] || !managedSubscriptionName(name) || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return result, ErrChanged
		}
		protected := false
		for _, ref := range referenced {
			if os.SameFile(info, ref) {
				protected = true
				break
			}
		}
		if protected {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("subscription cleanup stopped after %d files: %w", result.Removed, err)
		}
		if err := guard(); err != nil {
			return result, fmt.Errorf("subscription cleanup stopped after %d files: configuration changed", result.Removed)
		}
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("subscription cleanup stopped after %d files: %w", result.Removed, err)
		}
		rel := filepath.Join(subscriptionDir, name)
		body, err := safepath.ReadFileLimit(root, rel, maxSubscriptionBytes)
		if err != nil {
			return result, fmt.Errorf("subscription cleanup stopped after %d files: file changed", result.Removed)
		}
		if err := safepath.CompareAndRemove(root, rel, body); err != nil {
			return result, fmt.Errorf("subscription cleanup stopped after %d files: file changed", result.Removed)
		}
		result.Removed++
		result.Bytes += int64(len(body))
	}
	return result, nil
}
