package coreipc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/geoupdate"
)

const maxStageBytes = 128 << 20
const maxStageFiles = 4096

// snapshotDirectory runs in the unprivileged desktop process. It copies file
// contents, not links or filesystem objects, into the authenticated request.
// This ensures the elevated worker never opens paths supplied by the user.
func snapshotDirectory(root string) ([]StageFile, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("配置目录必须是绝对路径")
	}
	safeRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer safeRoot.Close()
	var files []StageFile
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// Pending downloads and interrupted update transactions are desktop
		// state, never input to the privileged worker.
		if !strings.ContainsAny(rel, `/\`) && strings.HasPrefix(strings.ToLower(rel), geoupdate.PrivatePrefix) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if !strings.ContainsAny(rel, `/\`) && (strings.EqualFold(rel, "agent") || strings.EqualFold(rel, "verge-script-outputs")) {
				return filepath.SkipDir
			}
			if strings.EqualFold(rel, filepath.Join("profiles", ".netflow-script-subscriptions")) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeType != 0 {
			return nil
		}
		if !strings.ContainsAny(rel, `/\`) {
			switch strings.ToLower(rel) {
			case "cache.db", "netflow-worker-cache.db", ".netflow.lock", ".netflow-stage-owner", "profiles.json", "settings.json", "kernel-options.json", "agent-rules.json":
				return nil
			}
		}
		// Verge's private recovery archive is interpreted by the desktop before
		// composition. The kernel needs the resulting configuration and provider
		// files, never the original archive containing subscription credentials.
		if isVergeRecoveryArchive(rel) {
			return nil
		}
		if len(files) >= maxStageFiles {
			return errors.New("配置目录文件过多，无法安全启动特权内核")
		}
		f, err := safeRoot.Open(rel)
		if err != nil {
			return fmt.Errorf("读取配置文件 %s: %w", rel, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxStageBytes-total+1))
		closeErr := f.Close()
		if readErr != nil {
			return fmt.Errorf("读取配置文件 %s: %w", rel, readErr)
		}
		if closeErr != nil {
			return closeErr
		}
		total += int64(len(data))
		if total > maxStageBytes {
			return errors.New("配置目录超过 128 MiB，无法安全启动特权内核")
		}
		files = append(files, StageFile{Path: rel, Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func isVergeRecoveryArchive(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "verge-imports") {
		return false
	}
	name := parts[1]
	if len(name) != 37 || name[0] != 'v' || !strings.EqualFold(name[33:], ".zip") {
		return false
	}
	_, err := hex.DecodeString(name[1:33])
	return err == nil
}
