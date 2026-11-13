package migration

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/profile"
	"go.yaml.in/yaml/v3"
)

func (s *Source) extensionData(id, kind string) []byte {
	if id == "" {
		return nil
	}
	if i, ok := s.itemByID[id]; ok {
		item := s.index.Items[i]
		if item.Type == kind {
			return s.files["profiles/"+item.File]
		}
	}
	return nil
}

func (s *Source) extensions(uid string) (profile.VergeExtensions, error) {
	i, ok := s.itemByID[uid]
	if !ok {
		return profile.VergeExtensions{}, errors.New("Verge 存档中的订阅不存在")
	}
	selected := &s.index.Items[i]
	if selected.Type != "remote" && selected.Type != "local" {
		return profile.VergeExtensions{}, errors.New("Verge 存档中的订阅类型无效")
	}
	proxies, groups, merge := selected.Option.Proxies, selected.Option.Groups, selected.Option.Merge
	if proxies == "" {
		proxies = "Proxies"
	}
	if groups == "" {
		groups = "Groups"
	}
	global := s.extensionData("Merge", "merge")
	result := profile.VergeExtensions{Proxies: s.extensionData(proxies, "proxies"), Groups: s.extensionData(groups, "groups"), GlobalMerge: global}
	if merge != "" && merge != "Merge" {
		result.ProfileMerge = s.extensionData(merge, "merge")
	}
	return result, nil
}

func hasExtensions(ext profile.VergeExtensions) bool {
	return len(ext.Proxies)+len(ext.Groups)+len(ext.GlobalMerge)+len(ext.ProfileMerge) > 0
}

// ArchivePath only accepts the managed archive belonging to this data root.
func ArchivePath(root, relative string) (string, error) {
	if !filepath.IsAbs(root) || !filepath.IsLocal(relative) || !strings.EqualFold(filepath.Dir(filepath.Clean(relative)), "verge-imports") {
		return "", errors.New("Verge 存档路径无效")
	}
	return managedFile(root, "verge-imports", relative)
}

// ComposeArchived applies data-only Verge enhancements from the original
// private archive. The archive and subscription files are never modified.
func ComposeArchived(root, relative, uid string, body []byte) ([]byte, string, [32]byte, error) {
	var empty [32]byte
	archive, err := ArchivePath(root, relative)
	if err != nil {
		return nil, "", empty, err
	}
	f, err := os.Open(archive)
	if err != nil {
		return nil, "", empty, err
	}
	data, readErr := readBounded(f, maxTotal)
	closeErr := f.Close()
	if readErr != nil {
		return nil, "", empty, readErr
	}
	if closeErr != nil {
		return nil, "", empty, closeErr
	}
	hash := sha256.Sum256(data)
	source, err := readArchiveExtensions(data, uid)
	if err != nil {
		return nil, "", empty, err
	}
	ext, err := source.extensions(uid)
	if err != nil {
		return nil, "", empty, err
	}
	result, err := profile.ComposeVergeExtensions(body, ext)
	return result, archive, hash, err
}

// Only the index and referenced extensions are decompressed during a reload;
// the potentially large original subscription archive remains untouched.
func readArchiveExtensions(archive []byte, uid string) (*Source, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	if len(zr.File) > 10000 {
		return nil, errors.New("Verge 存档条目过多")
	}
	entries := make(map[string]*zip.File)
	var total uint64
	for _, entry := range zr.File {
		name := entry.Name
		if entry.FileInfo().IsDir() {
			continue
		}
		if strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || entry.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Verge 存档包含不安全路径")
		}
		allowed := name == "profiles.yaml" || name == "verge.yaml" || name == "config.yaml" || name == "dns_config.yaml" || strings.HasPrefix(name, "profiles/") && safeFilename(strings.TrimPrefix(name, "profiles/"))
		if !allowed {
			continue
		}
		if _, exists := entries[name]; exists {
			return nil, errors.New("Verge 存档包含重复文件")
		}
		if entry.UncompressedSize64 > maxEntry {
			return nil, errors.New("Verge 存档文件过大")
		}
		total += entry.UncompressedSize64
		if total > maxTotal {
			return nil, errors.New("Verge 存档内容过大")
		}
		entries[name] = entry
	}
	read := func(name string) ([]byte, error) {
		entry := entries[name]
		if entry == nil {
			return nil, errors.New("Verge 存档缺少引用文件")
		}
		f, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := readBounded(f, maxEntry)
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		return data, closeErr
	}
	indexData, err := read("profiles.yaml")
	if err != nil {
		return nil, err
	}
	var index vergeIndex
	if err = yaml.Unmarshal(indexData, &index); err != nil {
		return nil, err
	}
	if len(index.Items) > 5000 {
		return nil, errors.New("订阅条目过多")
	}
	byID := make(map[string]int, len(index.Items))
	for i, item := range index.Items {
		if item.UID == "" || len(item.UID) > 128 || !safeFilename(item.File) {
			return nil, errors.New("Verge 存档索引无效")
		}
		if _, exists := byID[item.UID]; exists {
			return nil, errors.New("Verge 存档标识重复")
		}
		byID[item.UID] = i
	}
	i, ok := byID[uid]
	if !ok || (index.Items[i].Type != "remote" && index.Items[i].Type != "local") {
		return nil, errors.New("Verge 存档中的订阅不存在")
	}
	item := index.Items[i]
	wanted := []string{"Merge", item.Option.Merge, item.Option.Proxies, item.Option.Groups}
	if item.Option.Proxies == "" {
		wanted = append(wanted, "Proxies")
	}
	if item.Option.Groups == "" {
		wanted = append(wanted, "Groups")
	}
	files := make(map[string][]byte)
	for _, id := range wanted {
		if id == "" {
			continue
		}
		i, exists := byID[id]
		if !exists {
			continue
		}
		entry := index.Items[i]
		name := "profiles/" + entry.File
		if _, exists := files[name]; exists {
			continue
		}
		data, err := read(name)
		if err != nil {
			return nil, err
		}
		files[name] = data
	}
	return &Source{index: index, itemByID: byID, files: files}, nil
}
