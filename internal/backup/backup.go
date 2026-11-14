// Package backup provides offline NetFlow snapshots. Archives contain private
// subscription data and must be kept somewhere only the user can access.
package backup

import (
	"archive/zip"
	"context"
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
	"unicode"

	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/safepath"
)

const (
	manifestName     = "netflow-backup.json"
	maxFiles         = 4096
	maxFileBytes     = 128 << 20
	maxTotal         = 512 << 20
	maxManifestBytes = 4 << 20
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
const runningWarning = warning + " Runtime caches, logs and pending GeoData transactions are excluded."

// validName restricts names to a portable subset and rejects Windows device
// names, alternate streams, aliases with trailing spaces/dots, and traversal.
func validName(name string) bool {
	if len(name) > 4096 || !fs.ValidPath(name) || name == "." || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(name, `\:<>"|?*`) {
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
	return strings.EqualFold(name, ".netflow.lock") || strings.EqualFold(name, "agent") || strings.EqualFold(name, "backup-schedule.json")
}

func excludedOnline(name string) bool {
	if excluded(name) {
		return true
	}
	parts := strings.Split(name, "/")
	last := strings.ToLower(parts[len(parts)-1])
	if strings.HasPrefix(last, ".netflow-tmp-") {
		return true
	}
	if len(parts) != 1 {
		return false
	}
	switch last {
	case "cache.db", "cache.db-wal", "cache.db-shm", "netflow-worker-cache.db", "netflow-worker-cache.db-wal", "netflow-worker-cache.db-shm", "logs":
		return true
	default:
		return strings.HasPrefix(last, ".netflow-geodata-")
	}
}

func foldPath(value string) string {
	return strings.Map(func(r rune) rune {
		lowest := r
		for other := unicode.SimpleFold(r); other != r; other = unicode.SimpleFold(other) {
			if other < lowest {
				lowest = other
			}
		}
		return lowest
	}, value)
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
		key := foldPath(current)
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
	key := foldPath(name)
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
	return export(context.Background(), dir, destination, false)
}

// ExportRunning produces an optimistic snapshot without stopping the app.
// Volatile runtime caches, logs and in-progress GeoData transactions are
// excluded; a changed file set or file identity causes the backup to fail.
func ExportRunning(ctx context.Context, dir, destination string) (Manifest, error) {
	if ctx == nil {
		return Manifest{}, errors.New("backup context is required")
	}
	return export(ctx, dir, destination, true)
}

type source struct {
	rel  string
	info fs.FileInfo
}

func scanSources(ctx context.Context, rootPath string, running bool) ([]source, error) {
	var sources []source
	var total int64
	var index pathIndex
	err := filepath.WalkDir(rootPath, func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		if excluded(rel) || (running && excludedOnline(rel)) {
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
		return nil, err
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].rel < sources[j].rel })
	return sources, nil
}

func sameSources(a, b []source) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].rel != b[i].rel || !os.SameFile(a[i].info, b[i].info) || a[i].info.Size() != b[i].info.Size() || !a[i].info.ModTime().Equal(b[i].info.ModTime()) {
			return false
		}
	}
	return true
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func verifySourceHashes(ctx context.Context, root *os.Root, sources []source, entries []Entry) error {
	if len(sources) != len(entries) {
		return errors.New("configuration changed while backing up; retry")
	}
	for i, item := range sources {
		current, err := root.Open(filepath.FromSlash(item.rel))
		if err != nil {
			return err
		}
		opened, err := current.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(item.info, opened) {
			_ = current.Close()
			return errors.New("configuration changed while backing up; retry")
		}
		hash := sha256.New()
		n, err := io.Copy(hash, contextReader{ctx, io.LimitReader(current, maxFileBytes+1)})
		if closeErr := current.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if n != entries[i].Size || hex.EncodeToString(hash.Sum(nil)) != entries[i].SHA256 {
			return errors.New("configuration changed while backing up; retry")
		}
	}
	return nil
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func export(ctx context.Context, dir, destination string, running bool) (Manifest, error) {
	result := Manifest{Format: 1, Files: []Entry{}, Warning: warning}
	if running {
		result.Warning = runningWarning
	}
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
	sources, err := scanSources(ctx, rootPath, running)
	if err != nil {
		return result, err
	}
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
		n, e := io.Copy(io.MultiWriter(out, hash), contextReader{ctx, io.LimitReader(in, maxFileBytes+1)})
		after, statErr := in.Stat()
		closeErr := in.Close()
		if e != nil || statErr != nil || closeErr != nil || n != item.info.Size() || after.Size() != item.info.Size() || !after.ModTime().Equal(item.info.ModTime()) {
			err = errors.New("configuration changed or could not be read while backing up")
			break
		}
		result.Files = append(result.Files, Entry{Path: item.rel, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	if err == nil && running {
		var after []source
		after, err = scanSources(ctx, rootPath, true)
		if err == nil && !sameSources(sources, after) {
			err = errors.New("configuration changed while backing up; retry")
		}
		// Check actual contents again, not only timestamps, before publishing a
		// running snapshot. This also catches same-size changes on filesystems
		// with coarse timestamp resolution.
		if err == nil {
			err = verifySourceHashes(ctx, root, sources, result.Files)
		}
		if err == nil {
			after, err = scanSources(ctx, rootPath, true)
			if err == nil && !sameSources(sources, after) {
				err = errors.New("configuration changed while backing up; retry")
			}
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		var manifest []byte
		manifest, err = json.Marshal(result)
		if err == nil && len(manifest) > maxManifestBytes {
			err = errors.New("backup manifest exceeds size limit")
		}
		if err == nil {
			var out io.Writer
			out, err = zw.Create(manifestName)
			if err == nil {
				_, err = out.Write(manifest)
			}
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
	return RestoreContext(context.Background(), archive, destination)
}

// RestoreContext validates the archive before creating the new destination;
// cancellation during extraction may leave that newly created directory partial.
func RestoreContext(ctx context.Context, archive, destination string) (Manifest, error) {
	return restoreContext(ctx, archive, destination, "", nil, false)
}

// RestoreOutside additionally prevents creation inside a running config tree.
func RestoreOutside(ctx context.Context, archive, destination, forbiddenRoot string) (Manifest, error) {
	if !filepath.IsAbs(forbiddenRoot) {
		return Manifest{}, errors.New("active configuration path must be absolute")
	}
	return restoreContext(ctx, archive, destination, forbiddenRoot, nil, false)
}

// InspectFile validates an already-open backup without extracting it. The
// caller retains ownership of the file and must prevent concurrent mutation.
func InspectFile(ctx context.Context, file *os.File) (Manifest, error) {
	if file == nil {
		return Manifest{}, errors.New("backup file is required")
	}
	return restoreContext(ctx, "", "", "", file, true)
}

func restoreContext(ctx context.Context, archive, destination, forbiddenRoot string, provided *os.File, inspectOnly bool) (Manifest, error) {
	var result Manifest
	if ctx == nil {
		return result, errors.New("restore context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !inspectOnly && (!filepath.IsAbs(archive) || !filepath.IsAbs(destination)) {
		return result, errors.New("backup paths must be absolute")
	}
	archiveFile := provided
	if archiveFile == nil {
		var err error
		archiveFile, err = os.Open(archive)
		if err != nil {
			return result, err
		}
		defer archiveFile.Close()
	}
	info, err := archiveFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return result, errors.New("backup archive is not a regular file")
	}
	if err := validateZipDirectory(ctx, archiveFile, info.Size()); err != nil {
		return result, err
	}
	zr, err := zip.NewReader(archiveFile, info.Size())
	if err != nil {
		return result, err
	}
	if len(zr.File) > maxFiles+1 {
		return result, errors.New("backup has too many files")
	}
	files := make(map[string]*zip.File)
	var manifestFile *zip.File
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !f.Mode().IsRegular() {
			return result, errors.New("backup contains a nonregular entry")
		}
		if f.Name == manifestName {
			if manifestFile != nil || f.UncompressedSize64 > maxManifestBytes {
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
		key := foldPath(name)
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
	decoder := json.NewDecoder(io.LimitReader(manifestReader, maxManifestBytes+1))
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
	if result.Warning != runningWarning {
		result.Warning = warning
	}
	seen := make(map[string]bool)
	var index pathIndex
	var total int64
	for _, entry := range result.Files {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		key := foldPath(entry.Path)
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
		if err := verifyFile(ctx, f, entry, io.Discard); err != nil {
			return Manifest{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if inspectOnly {
		return result, nil
	}
	parentPath, err := safepath.Canonical(filepath.Dir(destination))
	if err != nil {
		return Manifest{}, err
	}
	if forbiddenRoot != "" {
		rootPath, err := safepath.Canonical(forbiddenRoot)
		if err != nil {
			return Manifest{}, err
		}
		if pathWithin(rootPath, parentPath) {
			return Manifest{}, errors.New("restore destination must be outside the running configuration")
		}
	}
	name := filepath.Base(destination)
	if !filepath.IsLocal(name) || name == "." {
		return Manifest{}, errors.New("invalid restore destination")
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return Manifest{}, err
	}
	defer parentRoot.Close()
	if err := parentRoot.Mkdir(name, 0700); err != nil {
		return Manifest{}, err
	}
	targetInfo, err := parentRoot.Lstat(name)
	if err != nil || !targetInfo.IsDir() {
		return Manifest{}, errors.New("restore destination changed after creation")
	}
	root, err := parentRoot.OpenRoot(name)
	if err != nil {
		return Manifest{}, fmt.Errorf("restore destination was created but could not be opened: %w", err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return Manifest{}, fmt.Errorf("restore destination could not be inspected: %w", err)
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !opened.IsDir() || !os.SameFile(targetInfo, opened) {
		_ = directory.Close()
		return Manifest{}, errors.New("restore destination changed after creation")
	}
	lock, err := appdir.AcquireRoot(root)
	if err != nil {
		_ = directory.Close()
		return Manifest{}, fmt.Errorf("restore destination was created but could not be locked: %w", err)
	}
	defer lock.Close()
	contents, readErr := directory.ReadDir(2)
	closeErr := directory.Close()
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(contents) != 1 || contents[0].Name() != ".netflow.lock" {
		return Manifest{}, errors.New("restore destination changed after creation")
	}
	for _, entry := range result.Files {
		if err := ctx.Err(); err != nil {
			return Manifest{}, fmt.Errorf("partial restore in new destination: %w", err)
		}
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
		err = verifyFile(ctx, files[foldPath(entry.Path)], entry, out)
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

func verifyFile(ctx context.Context, f *zip.File, entry Entry, dest io.Writer) error {
	in, err := f.Open()
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dest, hash), contextReader{ctx, io.LimitReader(in, entry.Size+1)})
	if closeErr := in.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if n != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return errors.New("backup file failed integrity verification")
	}
	return nil
}
