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
	"unicode/utf8"

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

func (s *Source) selectedRuleData(uid string) ([]byte, error) {
	i, ok := s.itemByID[uid]
	if !ok || (s.index.Items[i].Type != "remote" && s.index.Items[i].Type != "local") {
		return nil, errors.New("Verge 存档中的订阅不存在")
	}
	id := s.index.Items[i].Option.Rules
	if id == "" {
		id = "Rules"
	}
	return s.extensionData(id, "rules"), nil
}

// ReadArchivedRuleSequence reads only the rule sequence selected by the
// original profile (or Verge's default Rules entry). It does not apply it.
func ReadArchivedRuleSequence(root, relative, uid string) ([]byte, string, [32]byte, error) {
	var empty [32]byte
	if _, err := ArchivePath(root, relative); err != nil {
		return nil, "", empty, err
	}
	data, err := readManaged(root, "verge-imports", relative, maxTotal)
	if err != nil {
		return nil, "", empty, err
	}
	source, err := readArchiveSelected(data, uid, false, false, false, true)
	if err != nil {
		return nil, "", empty, err
	}
	rules, err := source.selectedRuleData(uid)
	if err != nil {
		return nil, "", empty, err
	}
	return rules, filepath.Join(root, relative), sha256.Sum256(data), nil
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
	return len(ext.Rules)+len(ext.Proxies)+len(ext.Groups)+len(ext.GlobalMerge)+len(ext.ProfileMerge) > 0
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
	return ComposeArchivedWithRules(root, relative, uid, body, false)
}

// ComposeArchivedWithRules optionally includes Verge's selected rule
// sequence before proxy/group extensions and merges. Legacy callers retain
// their previous behavior by using ComposeArchived.
func ComposeArchivedWithRules(root, relative, uid string, body []byte, includeRules bool) ([]byte, string, [32]byte, error) {
	var empty [32]byte
	if _, err := ArchivePath(root, relative); err != nil {
		return nil, "", empty, err
	}
	data, err := readManaged(root, "verge-imports", relative, maxTotal)
	if err != nil {
		return nil, "", empty, err
	}
	hash := sha256.Sum256(data)
	source, err := readArchiveSelected(data, uid, true, false, false, includeRules)
	if err != nil {
		return nil, "", empty, err
	}
	ext, err := source.extensions(uid)
	if err != nil {
		return nil, "", empty, err
	}
	if includeRules {
		ext.Rules, err = source.selectedRuleData(uid)
		if err != nil {
			return nil, "", empty, err
		}
	}
	result, err := profile.ComposeVergeExtensions(body, ext)
	return result, filepath.Join(root, relative), hash, err
}

// Only the index and referenced extensions are decompressed during a reload;
// the potentially large original subscription archive remains untouched.
func readArchiveExtensionsWithScript(archive []byte, uid string, includeScript, includeRules bool) (*Source, error) {
	return readArchiveSelected(archive, uid, true, includeScript, false, includeRules)
}
func readArchiveSelected(archive []byte, uid string, includeData, includeScript, includeGlobalScript, includeRules bool) (*Source, error) {
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
	var wanted []string
	if includeData {
		wanted = append(wanted, "Merge", item.Option.Merge, item.Option.Proxies, item.Option.Groups)
		if item.Option.Proxies == "" {
			wanted = append(wanted, "Proxies")
		}
		if item.Option.Groups == "" {
			wanted = append(wanted, "Groups")
		}
	}
	if includeScript {
		wanted = append(wanted, item.Option.Script)
	}
	if includeRules {
		id := item.Option.Rules
		if id == "" {
			id = "Rules"
		}
		wanted = append(wanted, id)
	}
	if includeGlobalScript {
		wanted = append(wanted, "Script")
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

// ArchivedScript is an explicitly retrievable artifact; reading it never
// authorizes or runs it. Hashes let later previews reject stale archives.
type ArchivedScript struct {
	UID    string
	Source []byte
	SHA256 [32]byte
}
type ArchivedScriptSnapshot struct {
	OriginalProfileName string
	Global              *ArchivedScript
	Profile             *ArchivedScript
	ArchivePath         string
	ArchiveSHA256       [32]byte
}

// ReadArchivedScripts returns the global Script and the referenced profile
// script from the original import snapshot. Missing or mismatched explicit
// profile references fail rather than silently selecting unrelated content.
func ReadArchivedScripts(root, relative, uid string) (ArchivedScriptSnapshot, error) {
	snapshot, _, err := readArchivedScriptSnapshot(root, relative, uid, false, ScriptSelection{Global: true, Profile: true}, false)
	return snapshot, err
}

// ReadArchivedCompositionSnapshot obtains data extensions and scripts from a
// single archive read, so preview inputs all share one immutable archive hash.
func ReadArchivedCompositionSnapshot(root, relative, uid string) (ArchivedScriptSnapshot, profile.VergeExtensions, error) {
	return readArchivedScriptSnapshot(root, relative, uid, true, ScriptSelection{Global: true, Profile: true}, false)
}

// ReadArchivedCompositionSelected avoids loading unselected scripts. In
// particular, a damaged script must not prevent previewing its removal.
func ReadArchivedCompositionSelected(root, relative, uid string, selection ScriptSelection) (ArchivedScriptSnapshot, profile.VergeExtensions, error) {
	return readArchivedScriptSnapshot(root, relative, uid, true, selection, false)
}

func ReadArchivedCompositionSelectedWithRules(root, relative, uid string, selection ScriptSelection, includeRules bool) (ArchivedScriptSnapshot, profile.VergeExtensions, error) {
	return readArchivedScriptSnapshot(root, relative, uid, true, selection, includeRules)
}

func readArchivedScriptSnapshot(root, relative, uid string, includeData bool, selection ScriptSelection, includeRules bool) (ArchivedScriptSnapshot, profile.VergeExtensions, error) {
	var empty profile.VergeExtensions
	var result ArchivedScriptSnapshot
	archivePath, err := ArchivePath(root, relative)
	if err != nil {
		return result, empty, err
	}
	data, err := readManaged(root, "verge-imports", relative, maxTotal)
	if err != nil {
		return result, empty, err
	}
	source, err := readArchiveSelected(data, uid, includeData, selection.Profile, selection.Global, includeRules)
	if err != nil {
		return result, empty, err
	}
	snapshot, err := archivedScriptsFromSource(source, uid, archivePath, sha256.Sum256(data), selection)
	if err != nil {
		return result, empty, err
	}
	if !includeData {
		return snapshot, empty, nil
	}
	extensions, err := source.extensions(uid)
	if err != nil {
		return result, empty, err
	}
	if includeRules {
		extensions.Rules, err = source.selectedRuleData(uid)
		if err != nil {
			return result, empty, err
		}
	}
	return snapshot, extensions, nil
}
func archivedScriptsFromSource(source *Source, uid, archivePath string, archiveHash [32]byte, selection ScriptSelection) (ArchivedScriptSnapshot, error) {
	var result ArchivedScriptSnapshot
	var err error
	index, ok := source.itemByID[uid]
	if !ok {
		return result, errors.New("Verge 订阅不存在")
	}
	item := source.index.Items[index]
	lookup := func(id string, required bool) (*ArchivedScript, error) {
		if id == "" {
			return nil, nil
		}
		i, found := source.itemByID[id]
		if !found {
			if required {
				return nil, errors.New("引用的 Verge 脚本不存在")
			}
			return nil, nil
		}
		entry := source.index.Items[i]
		if entry.Type != "script" {
			return nil, errors.New("Verge 脚本引用类型无效")
		}
		contents, found := source.files["profiles/"+entry.File]
		if !found {
			return nil, errors.New("Verge 脚本文件缺失")
		}
		if len(contents) > 1<<20 || !utf8.Valid(contents) || bytes.IndexByte(contents, 0) >= 0 {
			return nil, errors.New("Verge 脚本编码无效或超过大小限制")
		}
		return &ArchivedScript{UID: id, Source: append([]byte(nil), contents...), SHA256: sha256.Sum256(contents)}, nil
	}
	if selection.Global {
		result.Global, err = lookup("Script", false)
		if err != nil {
			return ArchivedScriptSnapshot{}, err
		}
	}
	if selection.Profile {
		result.Profile, err = lookup(item.Option.Script, item.Option.Script != "")
		if err != nil {
			return ArchivedScriptSnapshot{}, err
		}
	}
	result.OriginalProfileName = item.Name
	result.ArchivePath = archivePath
	result.ArchiveSHA256 = archiveHash
	return result, nil
}
