// Package backup provides offline NetFlow snapshots. Archives contain private
// subscription data and must be kept somewhere only the user can access.
package backup

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/safepath"
)

const (
	manifestName = "netflow-backup.json"
	maxFiles     = 4096
	maxFileBytes = 128 << 20
	maxTotal     = 512 << 20
)

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format  int     `json:"format"`
	Files   []Entry `json:"files"`
	Warning string  `json:"warning"`
}

const warning = "Contains private subscription data; WebDAV credentials protected by Windows DPAPI may not be recoverable on another account or computer."

// validName restricts names to a portable subset and rejects Windows device
// names, alternate streams, aliases with trailing spaces/dots, and traversal.
func validName(name string) bool {
	if !fs.ValidPath(name) || name == "." || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(name, `\:<>"|?*`) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.TrimRight(part, " .") != part {
			return false
		}
		for _, ch := range part {
			if ch < 32 {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		device := false
		if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
			number := []rune(base[3:])
			device = len(number) == 1 && strings.ContainsRune("123456789¹²³", number[0])
		}
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" || device {
			return false
		}
	}
	return true
}

func excluded(name string) bool {
	if strings.Contains(name, "/") {
		return false
	}
	return strings.EqualFold(name, ".netflow.lock") || strings.EqualFold(name, "agent")
}

func pathWithin(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	return err == nil && (rel == "." || (rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// pathIndex detects case aliases and file/directory conflicts before writing
// an archive or creating a restore destination.
type pathIndex struct {
	names    map[string]string
	files    map[string]bool
	children map[string]bool
}

func (p *pathIndex) add(name string, isFile bool) error {
	if p.names == nil {
		p.names, p.files, p.children = make(map[string]string), make(map[string]bool), make(map[string]bool)
	}
	for current := name; current != "."; current = path.Dir(current) {
		key := strings.ToLower(current)
		if prior, ok := p.names[key]; ok && prior != current {
			return errors.New("backup contains case-conflicting paths")
		}
		if p.files[key] && (current != name || !isFile) {
			return errors.New("backup contains conflicting paths")
		}
		if current != name {
			p.children[key] = true
		}
		p.names[key] = current
	}
	key := strings.ToLower(name)
	if isFile {
		if p.files[key] {
			return errors.New("backup contains duplicate files")
		}
		// The path may already exist as an implicit directory of an earlier file.
		if p.children[key] {
			return errors.New("backup contains conflicting paths")
		}
		p.files[key] = true
	}
	return nil
}

// Export reads a closed app's configuration. The caller must hold its directory
// lock for the whole operation. It never overwrites an existing archive.
func Export(dir, destination string) (Manifest, error) {
	result := Manifest{Format: 1, Files: []Entry{}, Warning: warning}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(destination) {
		return result, errors.New("backup paths must be absolute")
	}
	rootPath, err := safepath.Canonical(dir)
	if err != nil {
		return result, err
	}
	parent, err := safepath.Canonical(filepath.Dir(destination))
	if err != nil {
		return result, err
	}
	if pathWithin(rootPath, parent) {
		return result, errors.New("backup destination must be outside the configuration directory")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return result, err
	}
	defer root.Close()
	type source struct {
		rel  string
		info fs.FileInfo
	}
	var sources []source
	var total int64
	var index pathIndex
	err = filepath.WalkDir(rootPath, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(rootPath, name)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if excluded(rel) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !validName(rel) {
			return errors.New("configuration contains a nonportable path")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("configuration contains a symbolic link or junction")
		}
		if err := index.add(rel, !entry.IsDir()); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxFileBytes {
			return errors.New("configuration contains a nonregular or oversized file")
		}
		total += info.Size()
		if total > maxTotal || len(sources) >= maxFiles {
			return errors.New("configuration exceeds backup limits")
		}
		sources = append(sources, source{rel, info})
		return nil
	})
	if err != nil {
		return result, err
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].rel < sources[j].rel })
	outputRoot, err := os.OpenRoot(parent)
	if err != nil {
		return result, err
	}
	defer outputRoot.Close()
	outputName := filepath.Base(destination)
	f, err := outputRoot.OpenFile(outputName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	created, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return result, err
	}
	success := false
	defer func() {
		if !success {
			current, statErr := outputRoot.Lstat(outputName)
			if statErr == nil && os.SameFile(created, current) {
				_ = outputRoot.Remove(outputName)
			}
		}
	}()
	zw := zip.NewWriter(f)
	for _, item := range sources {
		in, e := root.Open(filepath.FromSlash(item.rel))
		if e != nil {
			err = e
			break
		}
		opened, e := in.Stat()
		if e != nil || !opened.Mode().IsRegular() || !os.SameFile(item.info, opened) {
			_ = in.Close()
			err = errors.New("configuration changed while backing up")
			break
		}
		header := &zip.FileHeader{Name: "files/" + item.rel, Method: zip.Deflate}
		header.SetMode(0600)
		out, e := zw.CreateHeader(header)
		if e != nil {
			_ = in.Close()
			err = e
			break
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, maxFileBytes+1))
		after, statErr := in.Stat()
		closeErr := in.Close()
		if e != nil || statErr != nil || closeErr != nil || n != item.info.Size() || after.Size() != item.info.Size() || !after.ModTime().Equal(item.info.ModTime()) {
			err = errors.New("configuration changed or could not be read while backing up")
			break
		}
		result.Files = append(result.Files, Entry{Path: item.rel, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	if err == nil {
		var out io.Writer
		out, err = zw.Create(manifestName)
		if err == nil {
			err = json.NewEncoder(out).Encode(result)
		}
	}
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := f.Sync(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return result, fmt.Errorf("backup failed: %w", err)
	}
	success = true
	return result, nil
}

// Restore validates the complete archive before creating a new destination.
// It refuses to overwrite even an empty existing directory. On an interrupted
// extraction a partial new directory can remain; no existing data is removed.
func Restore(archive, destination string) (Manifest, error) {
	var result Manifest
	if !filepath.IsAbs(archive) || !filepath.IsAbs(destination) {
		return result, errors.New("backup paths must be absolute")
	}
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return result, err
	}
	defer zr.Close()
	if len(zr.File) > maxFiles+1 {
		return result, errors.New("backup has too many files")
	}
	files := make(map[string]*zip.File)
	var manifestFile *zip.File
	for _, f := range zr.File {
		if !f.Mode().IsRegular() {
			return result, errors.New("backup contains a nonregular entry")
		}
		if f.Name == manifestName {
			if manifestFile != nil || f.UncompressedSize64 > 1<<20 {
				return result, errors.New("invalid backup manifest")
			}
			manifestFile = f
			continue
		}
		if !strings.HasPrefix(f.Name, "files/") {
			return result, errors.New("backup contains an unknown entry")
		}
		name := strings.TrimPrefix(f.Name, "files/")
		if !validName(name) || excluded(strings.Split(name, "/")[0]) || f.UncompressedSize64 > maxFileBytes {
			return result, errors.New("backup contains an invalid path or oversized file")
		}
		key := strings.ToLower(name)
		if _, exists := files[key]; exists {
			return result, errors.New("backup contains duplicate paths")
		}
		files[key] = f
	}
	if manifestFile == nil {
		return result, errors.New("backup manifest is missing")
	}
	manifestReader, err := manifestFile.Open()
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(io.LimitReader(manifestReader, (1<<20)+1))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&result)
	if err == nil {
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			err = errors.New("invalid backup manifest")
		}
	}
	if closeErr := manifestReader.Close(); err == nil {
		err = closeErr
	}
	if err != nil || result.Format != 1 || len(result.Files) != len(files) {
		return Manifest{}, errors.New("invalid backup manifest")
	}
	// Do not display warning text supplied by an untrusted archive.
	result.Warning = warning
	seen := make(map[string]bool)
	var index pathIndex
	var total int64
	for _, entry := range result.Files {
		key := strings.ToLower(entry.Path)
		f := files[key]
		if !validName(entry.Path) || seen[key] || f == nil || f.Name != "files/"+entry.Path || entry.Size < 0 || entry.Size > maxFileBytes || uint64(entry.Size) != f.UncompressedSize64 || len(entry.SHA256) != 64 {
			return Manifest{}, errors.New("backup manifest does not match its files")
		}
		seen[key] = true
		if err := index.add(entry.Path, true); err != nil {
			return Manifest{}, err
		}
		total += entry.Size
		if total > maxTotal {
			return Manifest{}, errors.New("backup exceeds restore limits")
		}
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if _, exists := files[parent]; exists {
				return Manifest{}, errors.New("backup contains conflicting paths")
			}
		}
		if err := verifyFile(f, entry, io.Discard); err != nil {
			return Manifest{}, err
		}
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return Manifest{}, err
	}
	lock, err := appdir.Acquire(destination)
	if err != nil {
		return Manifest{}, fmt.Errorf("restore destination was created but could not be locked: %w", err)
	}
	defer lock.Close()
	root, err := os.OpenRoot(destination)
	if err != nil {
		return Manifest{}, fmt.Errorf("restore destination was created but could not be opened: %w", err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return Manifest{}, fmt.Errorf("restore destination could not be inspected: %w", err)
	}
	contents, readErr := directory.ReadDir(2)
	closeErr := directory.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(contents) != 1 || contents[0].Name() != ".netflow.lock" {
		return Manifest{}, errors.New("restore destination changed after creation")
	}
	for _, entry := range result.Files {
		name := filepath.FromSlash(entry.Path)
		if parent := filepath.Dir(name); parent != "." {
			if err := root.MkdirAll(parent, 0700); err != nil {
				return Manifest{}, fmt.Errorf("partial restore in new destination: %w", err)
			}
		}
		out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return Manifest{}, fmt.Errorf("partial restore in new destination: %w", err)
		}
		err = verifyFile(files[strings.ToLower(entry.Path)], entry, out)
		if syncErr := out.Sync(); err == nil {
			err = syncErr
		}
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("partial restore in new destination: %w", err)
		}
	}
	return result, nil
}

func verifyFile(f *zip.File, entry Entry, dest io.Writer) error {
	in, err := f.Open()
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dest, hash), io.LimitReader(in, entry.Size+1))
	if closeErr := in.Close(); err == nil {
		err = closeErr
	}
	if err != nil || n != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return errors.New("backup file failed integrity verification")
	}
	return nil
}
