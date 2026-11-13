package coreipc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	var files []StageFile
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
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
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if !strings.ContainsAny(rel, `/\`) && strings.EqualFold(rel, "agent") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeType != 0 {
			return nil
		}
		if !strings.ContainsAny(rel, `/\`) {
			switch strings.ToLower(rel) {
			case "cache.db", "netflow-worker-cache.db", ".netflow.lock":
				return nil
			}
		}
		if len(files) >= maxStageFiles {
			return errors.New("配置目录文件过多，无法安全启动特权内核")
		}
		f, err := os.Open(path)
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
