//go:build darwin

package coreipc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const darwinStageParent = "/private/var/db"
const darwinStagePrefix = "netflow-kernel-"
const darwinMarker = ".netflow-stage-owner"
const darwinLock = ".netflow-stage-lock"
const darwinMarkerValue = "NetFlow protected kernel stage v1\n"

type darwinStage struct {
	dir    string
	lock   *os.File
	files  map[string]string
	hashes map[string][32]byte
}

func NewDarwinElevatedWorker() *Worker {
	w := NewWorker()
	w.stageFactory = createDarwinStage
	w.kernel.DisableExternalController()
	return w
}

func verifyDarwinDirectory(path string, private bool) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 || (private && st.Mode&0077 != 0) {
		return errors.New("特权内核目录访问控制不安全")
	}
	// macOS ACL entries take precedence over mode bits and can be inherited.
	// Fail closed if the system tool cannot prove that the directory has none.
	cmd := exec.Command("/bin/ls", "-ldne", path)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("无法检查特权目录 ACL: %w", err)
	}
	if !darwinACLAbsent(output) {
		return errors.New("特权内核目录不能包含 ACL")
	}
	return nil
}

// The parent is root-owned and not writable by ordinary users. A lock file
// distinguishes a live worker from a stage abandoned after process death.
func cleanDarwinStages() {
	entries, err := os.ReadDir(darwinStageParent)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, darwinStagePrefix) || len(name) <= len(darwinStagePrefix) {
			continue
		}
		dir := filepath.Join(darwinStageParent, name)
		if verifyDarwinDirectory(dir, true) != nil {
			continue
		}
		marker := filepath.Join(dir, darwinMarker)
		info, err := os.Lstat(marker)
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(darwinMarkerValue)) {
			continue
		}
		data, err := os.ReadFile(marker)
		if err != nil || string(data) != darwinMarkerValue {
			continue
		}
		f, err := os.OpenFile(filepath.Join(dir, darwinLock), os.O_RDWR|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		info, err = f.Stat()
		if err == nil && info.Mode().IsRegular() && unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
			_ = os.RemoveAll(dir)
		}
		_ = f.Close()
	}
}

func createDarwinStage() (fileStage, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("特权内核需要管理员权限")
	}
	for _, ancestor := range []string{"/private", "/private/var", darwinStageParent} {
		if err := verifyDarwinDirectory(ancestor, false); err != nil {
			return nil, err
		}
	}
	cleanDarwinStages()
	dir, err := os.MkdirTemp(darwinStageParent, darwinStagePrefix)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()
	if err = verifyDarwinDirectory(dir, true); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, darwinLock), os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, darwinMarker), []byte(darwinMarkerValue), 0600); err != nil {
		_ = lock.Close()
		return nil, err
	}
	ok = true
	return &darwinStage{dir: dir, lock: lock, files: make(map[string]string), hashes: make(map[string][32]byte)}, nil
}

func (s *darwinStage) Directory() string { return s.dir }

func (s *darwinStage) Apply(files []StageFile) error {
	if len(files) > maxStageFiles {
		return errors.New("特权内核输入文件过多")
	}
	seen := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if !filepath.IsLocal(file.Path) || file.Path == "." {
			return errors.New("特权内核输入路径无效")
		}
		key := strings.ToLower(filepath.Clean(file.Path))
		if key == darwinMarker || key == darwinLock || seen[key] {
			return errors.New("特权内核输入路径重复或保留")
		}
		seen[key] = true
		total += int64(len(file.Data))
		if total > maxStageBytes {
			return errors.New("特权内核输入超过大小限制")
		}
	}
	for key, old := range s.files {
		if !seen[key] {
			if err := os.Remove(filepath.Join(s.dir, old)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			delete(s.files, key)
			delete(s.hashes, key)
		}
	}
	for _, file := range files {
		key := strings.ToLower(filepath.Clean(file.Path))
		sum := sha256.Sum256(file.Data)
		if s.hashes[key] == sum {
			if info, err := os.Lstat(filepath.Join(s.dir, file.Path)); err == nil && info.Mode().IsRegular() {
				continue
			}
		}
		if err := s.writeFile(file); err != nil {
			return fmt.Errorf("写入隔离配置 %s: %w", file.Path, err)
		}
		s.files[key], s.hashes[key] = filepath.Clean(file.Path), sum
	}
	return nil
}

func (s *darwinStage) writeFile(file StageFile) error {
	parts := strings.Split(filepath.Clean(file.Path), string(os.PathSeparator))
	dir := s.dir
	for _, part := range parts[:len(parts)-1] {
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			if err = os.Mkdir(dir, 0700); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("隔离配置目录包含链接")
		}
	}
	path := filepath.Join(dir, parts[len(parts)-1])
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("隔离配置目标不是普通文件")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".netflow-stage-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(file.Data)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *darwinStage) Close() error {
	if verifyDarwinDirectory(darwinStageParent, false) != nil || verifyDarwinDirectory(s.dir, true) != nil || filepath.Dir(s.dir) != darwinStageParent || !strings.HasPrefix(filepath.Base(s.dir), darwinStagePrefix) {
		_ = s.lock.Close()
		return errors.New("拒绝清理意外的特权内核目录")
	}
	err := os.RemoveAll(s.dir)
	return errors.Join(err, s.lock.Close())
}
