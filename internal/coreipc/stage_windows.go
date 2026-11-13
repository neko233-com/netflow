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
	w.kernel.DisableExternalController()
	return w
}

type windowsStage struct {
	dir     string
	parent  windows.Handle
	handle  windows.Handle
	files   map[string]string
	hashes  map[string][32]byte
	cleaned []string
}

const stageMarkerName = ".netflow-stage-owner"
const stageMarkerContent = "NetFlow protected kernel stage v1\n"

func openLockedDirectory(path string, deleteAccess bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	if deleteAccess {
		access |= windows.DELETE
	}
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
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

func verifyStageSecurity(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	admins, aerr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, serr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	control, _, cerr := sd.Control()
	acl, _, derr := sd.DACL()
	if err != nil || aerr != nil || serr != nil || cerr != nil || derr != nil || owner == nil || !owner.Equals(admins) || control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 2 {
		return errors.New("特权内核目录访问控制不安全")
	}
	var haveAdmins, haveSystem bool
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			return errors.New("特权内核目录访问控制不安全")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(admins):
			haveAdmins = true
		case sid.Equals(system):
			haveSystem = true
		default:
			return errors.New("特权内核目录包含意外的访问者")
		}
	}
	if !haveAdmins || !haveSystem {
		return errors.New("特权内核目录访问控制不完整")
	}
	return nil
}

func safeStageRoot(path, parent string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(parent) {
		return false
	}
	base := filepath.Base(path)
	nonce := strings.TrimPrefix(base, "NetFlowKernel-")
	_, err := hex.DecodeString(nonce)
	return strings.EqualFold(filepath.Dir(path), parent) && strings.HasPrefix(base, "NetFlowKernel-") && len(nonce) == 32 && err == nil
}

// clearLockedStage keeps the directory handle open without FILE_SHARE_DELETE,
// so no other process can swap its root while privileged cleanup is running.
func clearLockedStage(dir, parent string, h windows.Handle) error {
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(h)
		}
	}()
	if !safeStageRoot(dir, parent) {
		return errors.New("拒绝清理意外的特权内核目录")
	}
	var original windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &original); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), stageMarkerName) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." || !filepath.IsLocal(rel) {
			return errors.New("拒绝清理意外的隔离文件")
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	marker := filepath.Join(dir, stageMarkerName)
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Windows may reject opening or renaming children while a directory
	// handle requests DELETE. Hold a non-delete lock during file cleanup,
	// then reacquire a delete handle and verify the same filesystem object.
	if err := windows.CloseHandle(h); err != nil {
		return err
	}
	closed = true
	deleteHandle, err := openLockedDirectory(dir, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(deleteHandle)
	var current windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(deleteHandle, &current); err != nil {
		return err
	}
	if !sameDirectory(original, current) || verifyStageSecurity(deleteHandle) != nil {
		return errors.New("拒绝清理已替换的特权内核目录")
	}
	remove := byte(1)
	return windows.SetFileInformationByHandle(deleteHandle, windows.FileDispositionInfo, &remove, 1)
}

func sameDirectory(a, b windows.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow
}

func cleanupAbandonedStages(parent string) []string {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var cleaned []string
	for _, entry := range entries {
		path := filepath.Join(parent, entry.Name())
		if !entry.IsDir() || !safeStageRoot(path, parent) {
			continue
		}
		// A live worker's handle does not share DELETE, so this open fails and
		// its files are never considered for cleanup.
		h, err := openLockedDirectory(path, true)
		if err != nil {
			continue
		}
		var original windows.ByHandleFileInformation
		valid := verifyStageSecurity(h) == nil && windows.GetFileInformationByHandle(h, &original) == nil
		_ = windows.CloseHandle(h)
		if !valid {
			continue
		}
		readHandle, err := openLockedDirectory(path, false)
		if err != nil {
			continue
		}
		var current windows.ByHandleFileInformation
		valid = windows.GetFileInformationByHandle(readHandle, &current) == nil && sameDirectory(original, current) && verifyStageSecurity(readHandle) == nil
		marker := filepath.Join(path, stageMarkerName)
		info, statErr := os.Lstat(marker)
		if valid && statErr == nil && info.Mode().IsRegular() && info.Size() == int64(len(stageMarkerContent)) {
			data, readErr := os.ReadFile(marker)
			if readErr == nil && string(data) == stageMarkerContent {
				if clearLockedStage(path, parent, readHandle) == nil {
					cleaned = append(cleaned, path)
				}
				continue
			}
		}
		_ = windows.CloseHandle(readHandle)
	}
	return cleaned
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
	parent, err := openLockedDirectory(parentPath, false)
	if err != nil {
		return nil, fmt.Errorf("保护特权临时目录: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.CloseHandle(parent)
		}
	}()
	cleaned := cleanupAbandonedStages(parentPath)
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
		h, err := openLockedDirectory(dir, false)
		if err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
		if err := verifyStageSecurity(h); err != nil {
			_ = windows.CloseHandle(h)
			_ = os.Remove(dir)
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, stageMarkerName), []byte(stageMarkerContent), 0600); err != nil {
			_ = windows.CloseHandle(h)
			_ = os.Remove(dir)
			return nil, err
		}
		ok = true
		return &windowsStage{dir: dir, parent: parent, handle: h, cleaned: cleaned}, nil
	}
	return nil, errors.New("无法创建特权内核隔离目录")
}

func (s *windowsStage) Directory() string       { return s.dir }
func (s *windowsStage) CleanedStages() []string { return append([]string(nil), s.cleaned...) }

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
		if key == stageMarkerName {
			return errors.New("特权内核输入包含保留文件名")
		}
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
	if err != nil {
		errs = append(errs, err)
		if closeErr := windows.CloseHandle(s.handle); closeErr != nil {
			errs = append(errs, closeErr)
		}
	} else if err := clearLockedStage(s.dir, filepath.Join(winDir, "Temp"), s.handle); err != nil {
		errs = append(errs, err)
	}
	if err := windows.CloseHandle(s.parent); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
