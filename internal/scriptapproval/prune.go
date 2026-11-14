package scriptapproval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/vergescript"
)

type PruneResult struct {
	Removed int   `json:"removed"`
	Bytes   int64 `json:"bytes"`
}

// Prune removes only unreferenced files with NetFlow's exact cache naming
// format. Guard must recheck catalog state immediately before each removal.
// This cannot eliminate a simultaneous external writer's final race window.
func Prune(ctx context.Context, root string, refs []Approval, guard func() error) (PruneResult, error) {
	var result PruneResult
	if ctx == nil || guard == nil {
		return result, errors.New("cache cleanup is not configured")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	kept := make(map[string]bool, len(refs))
	for _, approval := range refs {
		path, err := cachePath(approval)
		if err != nil {
			return result, ErrChanged
		}
		kept[filepath.Base(path)] = true
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	dir, _, err := safepath.Parent(root, filepath.Join("verge-script-outputs", "placeholder"), false)
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
	closeErr := f.Close()
	rootErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || rootErr != nil || len(entries) > 4096 {
		return result, ErrChanged
	}
	for _, entry := range entries {
		name := entry.Name()
		if kept[name] || !strings.HasSuffix(name, ".json") || !validDigest(strings.TrimSuffix(name, ".json")) || !entry.Type().IsRegular() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("cache cleanup stopped after %d files: %w", result.Removed, err)
		}
		if err := guard(); err != nil {
			return result, fmt.Errorf("cache cleanup stopped after %d files: configuration changed", result.Removed)
		}
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("cache cleanup stopped after %d files: %w", result.Removed, err)
		}
		rel := filepath.Join("verge-script-outputs", name)
		body, err := safepath.ReadFileLimit(root, rel, vergescript.MaxJSONBytes)
		if err != nil {
			return result, fmt.Errorf("cache cleanup stopped after %d files: output changed", result.Removed)
		}
		if err := safepath.CompareAndRemove(root, rel, body); err != nil {
			return result, fmt.Errorf("cache cleanup stopped after %d files: output changed", result.Removed)
		}
		result.Removed++
		result.Bytes += int64(len(body))
	}
	return result, nil
}
