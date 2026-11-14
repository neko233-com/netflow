package safepath

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrChanged means another process modified a file during a transaction.
var ErrChanged = errors.New("file changed during operation")

const MaxFileBytes = 128 << 20

// Parent opens each existing directory by handle, rejects links and detects
// replacement between inspection and opening. The caller owns the returned root.
func Parent(base, relative string, create bool) (*os.Root, string, error) {
	if base == "" || !filepath.IsLocal(relative) || relative == "." {
		return nil, "", errors.New("invalid managed path")
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		info, e := root.Lstat(part)
		if errors.Is(e, os.ErrNotExist) && create {
			if e = root.Mkdir(part, 0700); e != nil && !errors.Is(e, os.ErrExist) {
				_ = root.Close()
				return nil, "", e
			}
			info, e = root.Lstat(part)
		}
		if e != nil {
			_ = root.Close()
			return nil, "", e
		}
		if !info.IsDir() {
			_ = root.Close()
			return nil, "", errors.New("managed directory is a link or not a directory")
		}
		next, e := root.OpenRoot(part)
		if e != nil {
			_ = root.Close()
			return nil, "", e
		}
		f, e := next.Open(".")
		if e != nil {
			_ = next.Close()
			_ = root.Close()
			return nil, "", e
		}
		opened, e := f.Stat()
		closeErr := f.Close()
		if e != nil || closeErr != nil || !opened.IsDir() || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = root.Close()
			return nil, "", ErrChanged
		}
		_ = root.Close()
		root = next
	}
	return root, parts[len(parts)-1], nil
}

// OpenRead opens a regular file without following its final link. The file
// handle remains valid after its containing root is closed.
func OpenRead(base, relative string) (*os.File, error) {
	root, name, err := Parent(base, relative, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("managed file is a link or not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, ErrChanged
	}
	return f, nil
}

func ReadFile(base, relative string) ([]byte, error) {
	return ReadFileLimit(base, relative, MaxFileBytes)
}

// ReadFileLimit applies a smaller caller-specific bound while preserving the
// same directory and final-file checks as ReadFile.
func ReadFileLimit(base, relative string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > MaxFileBytes {
		return nil, errors.New("invalid managed file size limit")
	}
	f, err := OpenRead(base, relative)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("managed file exceeds size limit")
	}
	return data, nil
}

// OpenLock opens or creates a regular lock file without following links.
func OpenLock(base, relative string) (*os.File, error) {
	root, name, err := Parent(base, relative, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return OpenLockAt(root, name)
}

// OpenLockAt operates inside an already pinned directory; it does not take
// ownership of root.
func OpenLockAt(root *os.Root, name string) (*os.File, error) {
	if root == nil || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return nil, errors.New("invalid lock path")
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		before, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	if before != nil && !before.Mode().IsRegular() {
		return nil, errors.New("lock file is a link or not a regular file")
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	after, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !opened.Mode().IsRegular() || !after.Mode().IsRegular() || !os.SameFile(opened, after) || (before != nil && !os.SameFile(before, opened)) {
		_ = f.Close()
		return nil, ErrChanged
	}
	if err := requireSingleLink(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func randomName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return ".netflow-tmp-" + hex.EncodeToString(value[:]), nil
}

func unchanged(root *os.Root, name string, before fs.FileInfo) bool {
	now, err := root.Lstat(name)
	if before == nil {
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && now.Mode().IsRegular() && os.SameFile(before, now) && before.Size() == now.Size() && before.ModTime().Equal(now.ModTime())
}

// WriteFile atomically replaces a regular file or creates a missing file. It
// refuses links and checks for a conflicting replacement before the rename.
func WriteFile(base, relative string, data []byte) error {
	return writeFile(base, relative, nil, false, data)
}

// CompareAndWrite also requires the existing bytes to match expected. A nil
// expected value means the destination must be absent.
func CompareAndWrite(base, relative string, expected, data []byte) error {
	return writeFile(base, relative, expected, true, data)
}

func writeFile(base, relative string, expected []byte, compare bool, data []byte) error {
	if len(data) > MaxFileBytes {
		return errors.New("managed file exceeds size limit")
	}
	root, name, err := Parent(base, relative, false)
	if err != nil {
		return err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		before, err = nil, nil
	}
	if err != nil {
		return err
	}
	if before != nil && !before.Mode().IsRegular() {
		return errors.New("managed file is a link or not a regular file")
	}
	if compare {
		if expected == nil && before != nil || expected != nil && before == nil {
			return ErrChanged
		}
		if before != nil {
			f, e := root.Open(name)
			if e != nil {
				return e
			}
			opened, e := f.Stat()
			if e != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
				_ = f.Close()
				return ErrChanged
			}
			current, e := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			if len(current) > MaxFileBytes || !bytes.Equal(current, expected) {
				return ErrChanged
			}
		}
	}
	tmp, err := randomName()
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	created, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		if current, e := root.Lstat(tmp); e == nil && os.SameFile(created, current) {
			_ = root.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if !unchanged(root, name, before) {
		return ErrChanged
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("replace managed file: %w", err)
	}
	return nil
}

// Created tracks an exclusively-created file so rollback cannot remove a
// different file that appeared at the same name.
type Created struct {
	root *os.Root
	name string
	info fs.FileInfo
}

func CreateExclusive(base, relative string, data []byte, createParents bool) (*Created, error) {
	if len(data) > MaxFileBytes {
		return nil, errors.New("managed file exceeds size limit")
	}
	root, name, err := Parent(base, relative, createParents)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	created := &Created{root: root, name: name, info: info}
	if err != nil {
		_ = created.Remove()
		_ = root.Close()
		return nil, err
	}
	return created, nil
}

func (c *Created) Remove() error {
	if c == nil || c.root == nil || c.info == nil {
		return errors.New("created file is unavailable")
	}
	current, err := c.root.Lstat(c.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(c.info, current) {
		return ErrChanged
	}
	return c.root.Remove(c.name)
}

func (c *Created) Close() error {
	if c == nil || c.root == nil {
		return nil
	}
	err := c.root.Close()
	c.root = nil
	return err
}

// Removal pins the containing directory and checks the final object before and
// after related metadata changes. Missing files may be tolerated by callers.
type Removal struct {
	root *os.Root
	name string
	info fs.FileInfo
}

func PrepareRemoval(base, relative string) (*Removal, error) {
	root, name, err := Parent(base, relative, false)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		info, err = nil, nil
	}
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if info != nil && !info.Mode().IsRegular() {
		_ = root.Close()
		return nil, errors.New("managed file is a link or not a regular file")
	}
	return &Removal{root: root, name: name, info: info}, nil
}

func (r *Removal) Remove() error {
	if r == nil || r.root == nil {
		return errors.New("managed removal is unavailable")
	}
	if !unchanged(r.root, r.name, r.info) {
		return ErrChanged
	}
	if r.info == nil {
		return nil
	}
	return r.root.Remove(r.name)
}

func (r *Removal) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	return err
}

// CompareAndRemove removes only a regular file with the expected contents.
func CompareAndRemove(base, relative string, expected []byte) error {
	root, name, err := Parent(base, relative, false)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("managed file is a link or not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = f.Close()
		return ErrChanged
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(data) > MaxFileBytes || !bytes.Equal(data, expected) || !unchanged(root, name, info) {
		return ErrChanged
	}
	return root.Remove(name)
}
