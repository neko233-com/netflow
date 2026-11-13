//go:build windows

package coreipc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewElevatedWorker prevents the privileged kernel from opening the user's
// writable configuration tree. Input files arrive over authenticated IPC and
// are materialized in a private, administrator-owned directory.
func NewElevatedWorker() *Worker {
	w := NewWorker()
	w.stageFactory = createWindowsStage
	return w
}

type windowsStage struct {
	dir    string
	parent windows.Handle
	handle windows.Handle
	files  map[string]string
	hashes map[string][32]byte
}

func openLockedDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.CloseHandle(h)
		if err != nil {
			return 0, err
		}
		return 0, errors.New("特权内核目录不能是重解析点")
	}
	return h, nil
}

func createWindowsStage() (fileStage, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("特权内核需要管理员权限")
	}
	winDir, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Join(winDir, "Temp")
	parent, err := openLockedDirectory(parentPath)
	if err != nil {
		return nil, fmt.Errorf("保护特权临时目录: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.CloseHandle(parent)
		}
	}()
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for i := 0; i < 10; i++ {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		dir := filepath.Join(parentPath, "NetFlowKernel-"+hex.EncodeToString(nonce[:]))
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return nil, err
		}
		if err = windows.CreateDirectory(name, &sa); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		} else if err != nil {
			return nil, err
		}
		h, err := openLockedDirectory(dir)
		if err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
		ownerSD, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			_ = windows.CloseHandle(h)
			_ = os.Remove(dir)
			return nil, err
		}
		owner, _, err := ownerSD.Owner()
		admins, sidErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil || sidErr != nil || !owner.Equals(admins) {
			_ = windows.CloseHandle(h)
			_ = os.Remove(dir)
			return nil, errors.New("特权内核目录所有者不安全")
		}
		ok = true
		return &windowsStage{dir: dir, parent: parent, handle: h}, nil
	}
	return nil, errors.New("无法创建特权内核隔离目录")
}

func (s *windowsStage) Directory() string { return s.dir }

func (s *windowsStage) Apply(files []StageFile) error {
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
		if seen[key] {
			return errors.New("特权内核输入路径重复")
		}
		seen[key] = true
		total += int64(len(file.Data))
		if total > maxStageBytes {
			return errors.New("特权内核输入超过大小限制")
		}
	}
	if s.files == nil {
		s.files = make(map[string]string, len(files))
	}
	if s.hashes == nil {
		s.hashes = make(map[string][32]byte, len(files))
	}
	for key, oldPath := range s.files {
		if !seen[key] {
			if err := os.Remove(filepath.Join(s.dir, oldPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("移除旧隔离配置 %s: %w", oldPath, err)
			}
			delete(s.hashes, key)
			delete(s.files, key)
		}
	}
	for _, file := range files {
		key := strings.ToLower(filepath.Clean(file.Path))
		sum := sha256.Sum256(file.Data)
		if s.hashes[key] == sum {
			if info, err := os.Lstat(filepath.Join(s.dir, filepath.Clean(file.Path))); err == nil && info.Mode().IsRegular() {
				s.files[key] = filepath.Clean(file.Path)
				continue
			}
		}
		if err := s.writeFile(file); err != nil {
			return fmt.Errorf("写入隔离配置 %s: %w", file.Path, err)
		}
		s.hashes[key] = sum
		s.files[key] = filepath.Clean(file.Path)
	}
	return nil
}

func (s *windowsStage) writeFile(file StageFile) error {
	rel := filepath.Clean(file.Path)
	parts := strings.Split(rel, string(os.PathSeparator))
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
			return errors.New("隔离配置目录包含重解析点")
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
	f, err := os.CreateTemp(dir, ".netflow-stage-*")
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

func (s *windowsStage) Close() error {
	var errs []error
	winDir, err := windows.GetWindowsDirectory()
	base := filepath.Base(s.dir)
	nonce := strings.TrimPrefix(base, "NetFlowKernel-")
	_, nonceErr := hex.DecodeString(nonce)
	safeRoot := err == nil && strings.EqualFold(filepath.Dir(s.dir), filepath.Join(winDir, "Temp")) && strings.HasPrefix(base, "NetFlowKernel-") && len(nonce) == 32 && nonceErr == nil
	if !safeRoot {
		errs = append(errs, errors.New("拒绝清理意外的特权内核目录"))
	} else {
		entries, readErr := os.ReadDir(s.dir)
		if readErr != nil {
			errs = append(errs, readErr)
		} else {
			for _, e := range entries {
				path := filepath.Join(s.dir, e.Name())
				rel, relErr := filepath.Rel(s.dir, path)
				if relErr != nil || rel == "." || !filepath.IsLocal(rel) {
					errs = append(errs, errors.New("拒绝清理意外的隔离文件"))
					continue
				}
				if err := os.RemoveAll(path); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := windows.CloseHandle(s.handle); err != nil {
		errs = append(errs, err)
	}
	if safeRoot {
		if err := os.Remove(s.dir); err != nil {
			errs = append(errs, err)
		}
	}
	if err := windows.CloseHandle(s.parent); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
