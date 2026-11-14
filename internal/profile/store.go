package profile

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/scriptmeta"
)

// CatalogItem is one subscription in profiles.json. It is not ImportHTTP's
// Item: that type is the fetch result, this one is the saved index.
type CatalogItem struct {
	UID         string         `json:"uid"`
	Name        string         `json:"name"`
	Description string         `json:"desc,omitempty"`
	URL         string         `json:"url,omitempty"`
	Type        string         `json:"type"`
	Home        string         `json:"home,omitempty"`
	Updated     time.Time      `json:"updated,omitempty"`
	Used        int64          `json:"used,omitempty"`
	Total       int64          `json:"total,omitempty"`
	Expire      time.Time      `json:"expire,omitempty"`
	File        string         `json:"file,omitempty"`
	Option      CatalogOption  `json:"option"`
	Selected    []SelectedNode `json:"selected,omitempty"`
}

// SelectedNode is one group→node choice stored on a subscription, matching
// Verge's profiles selected list.
type SelectedNode struct {
	Name string `json:"name"`
	Now  string `json:"now"`
}

// CatalogOption is the remote form and the extension slots stored in the index.
type CatalogOption struct {
	UpdateInterval      int                  `json:"update_interval,omitempty"`
	UseSystemProxy      bool                 `json:"use_system_proxy,omitempty"`
	UseClashProxy       bool                 `json:"use_clash_proxy,omitempty"`
	AcceptInvalid       bool                 `json:"allow_insecure,omitempty"`
	AllowAutoUpdate     bool                 `json:"allow_auto_update,omitempty"`
	Rules               string               `json:"rules,omitempty"`
	Proxies             string               `json:"proxies,omitempty"`
	Groups              string               `json:"groups,omitempty"`
	Merge               string               `json:"merge,omitempty"`
	Script              string               `json:"script,omitempty"`
	UserAgent           string               `json:"user_agent,omitempty"`
	TimeoutSeconds      int                  `json:"timeout,omitempty"`
	DNSEnabled          bool                 `json:"dns_override_enabled,omitempty"`
	DNSOverride         string               `json:"dns_override,omitempty"`
	DNSVergeMerge       bool                 `json:"dns_verge_merge,omitempty"`
	DNSVergeHosts       string               `json:"dns_verge_hosts,omitempty"`
	VergeArchive        string               `json:"verge_archive,omitempty"`
	VergeUID            string               `json:"verge_uid,omitempty"`
	VergeExtensions     bool                 `json:"verge_extensions,omitempty"`
	VergeScriptApproval *scriptmeta.Approval `json:"verge_script_approval,omitempty"`
	VergeScriptPrevious *scriptmeta.Previous `json:"verge_script_previous,omitempty"`
	VergeProviderPaths  map[string]string    `json:"verge_provider_paths,omitempty"`
}

// MetadataPatch changes only specified fields. Download options apply only to
// remote profiles; the subscription URL and extension data are never changed.
type MetadataPatch struct {
	Name, Description, UserAgent                            *string
	Timeout, Interval                                       *int
	AutoUpdate, UseCoreProxy, UseSystemProxy, AllowInsecure *bool
}

// Preserve the input name used by a disabled script's previous approval.
// The referenced file may be shared with the current profile until an update
// replaces it; SharedProfileFile treats the retained reference as shared.
func retainScriptHistoryBeforeRename(item *CatalogItem, name string) error {
	if item == nil || name == item.Name || item.Option.VergeScriptApproval != nil {
		return nil
	}
	previous := item.Option.VergeScriptPrevious
	if previous == nil || previous.Approval == nil || previous.Subscription != nil {
		return nil
	}
	if err := validateManagedProfilePath(item.File); err != nil {
		return errors.New("无法保留脚本回滚所需的订阅文件")
	}
	copy := *previous
	copy.Subscription = &scriptmeta.SubscriptionSnapshot{File: item.File, URL: item.URL, Name: item.Name, Updated: item.Updated, Used: item.Used, Total: item.Total, Expire: item.Expire}
	item.Option.VergeScriptPrevious = &copy
	return nil
}

func (p MetadataPatch) hasDownloadOptions() bool {
	return p.UserAgent != nil || p.Timeout != nil || p.Interval != nil || p.AutoUpdate != nil || p.UseCoreProxy != nil || p.UseSystemProxy != nil || p.AllowInsecure != nil
}

// PatchMetadata loads and conditionally commits one catalog snapshot, so a
// concurrent edit is rejected rather than overwritten.
func (s *Store) PatchMetadata(uid string, patch MetadataPatch) (CatalogItem, error) {
	if uid == "" || (patch.Name == nil && patch.Description == nil && !patch.hasDownloadOptions()) {
		return CatalogItem{}, errors.New("profile id and at least one metadata field are required")
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return CatalogItem{}, err
	}
	for i := range f.Items {
		item := &f.Items[i]
		if item.UID != uid {
			continue
		}
		if patch.hasDownloadOptions() && item.Type != "remote" {
			return CatalogItem{}, errors.New("download options require a remote profile")
		}
		if patch.Name != nil {
			name := strings.TrimSpace(*patch.Name)
			if name == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
				return CatalogItem{}, errors.New("invalid profile name")
			}
			if item.Option.VergeScriptApproval != nil && name != item.Name {
				return CatalogItem{}, errors.New("已启用的 Verge 脚本绑定订阅名称；请先关闭脚本，修改名称后重新预览并启用")
			}
			if err := retainScriptHistoryBeforeRename(item, name); err != nil {
				return CatalogItem{}, err
			}
			item.Name = name
		}
		if patch.Description != nil {
			desc := strings.TrimSpace(*patch.Description)
			if len(desc) > 2048 || strings.ContainsRune(desc, '\x00') {
				return CatalogItem{}, errors.New("invalid profile description")
			}
			item.Description = desc
		}
		if patch.UserAgent != nil {
			ua := strings.TrimSpace(*patch.UserAgent)
			if len(ua) > 512 || strings.ContainsAny(ua, "\r\n\x00") {
				return CatalogItem{}, errors.New("invalid user agent")
			}
			item.Option.UserAgent = ua
		}
		if patch.Timeout != nil {
			if *patch.Timeout < 1 || *patch.Timeout > 300 {
				return CatalogItem{}, errors.New("timeout must be between 1 and 300 seconds")
			}
			item.Option.TimeoutSeconds = *patch.Timeout
		}
		if patch.Interval != nil {
			if *patch.Interval < 1 || *patch.Interval > 43200 {
				return CatalogItem{}, errors.New("interval must be between 1 and 43200 minutes")
			}
			item.Option.UpdateInterval = *patch.Interval
		}
		if patch.AutoUpdate != nil {
			item.Option.AllowAutoUpdate = *patch.AutoUpdate
		}
		if patch.UseCoreProxy != nil {
			item.Option.UseClashProxy = *patch.UseCoreProxy
		}
		if patch.UseSystemProxy != nil {
			item.Option.UseSystemProxy = *patch.UseSystemProxy
		}
		if patch.AllowInsecure != nil {
			item.Option.AcceptInvalid = *patch.AllowInsecure
		}
		if err := s.SaveIfUnchanged(f, snapshot); err != nil {
			return CatalogItem{}, err
		}
		return *item, nil
	}
	return CatalogItem{}, errors.New("profile not found")
}

// File is profiles.json.
type File struct {
	Items   []CatalogItem `json:"items"`
	Current string        `json:"current"`
}

// Store loads and saves the profile list inside a config directory.
type Store struct {
	dir string
}

// NewStore returns a store for dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Load returns an empty file when profiles.json is missing.
func (s *Store) Load() (File, error) {
	f, _, err := s.LoadSnapshot()
	return f, err
}

// LoadSnapshot associates the parsed catalog with the hash of the exact bytes
// used to parse it. A missing file is represented by the zero hash.
func (s *Store) LoadSnapshot() (File, [32]byte, error) {
	var empty [32]byte
	if s == nil || s.dir == "" {
		return File{}, empty, errors.New("profile store has no directory")
	}
	b, err := safepath.ReadFile(s.dir, "profiles.json")
	if errors.Is(err, os.ErrNotExist) {
		return File{}, empty, nil
	}
	if err != nil {
		return File{}, empty, err
	}
	hash := sha256.Sum256(b)
	if len(strings.TrimSpace(string(b))) == 0 {
		return File{}, hash, nil
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, empty, err
	}
	return f, hash, nil
}

// Save writes profiles.json.
func (s *Store) Save(f File) error {
	if s == nil || s.dir == "" {
		return errors.New("profile store has no directory")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return safepath.WriteFile(s.dir, "profiles.json", b)
}

// LoadForUpdate retains the exact catalog bytes for a subsequent conditional
// commit. A nil snapshot represents a catalog that does not yet exist.
func (s *Store) LoadForUpdate() (File, []byte, error) {
	f, expectedHash, err := s.LoadSnapshot()
	if err != nil {
		return File{}, nil, err
	}
	b, err := safepath.ReadFile(s.dir, "profiles.json")
	if errors.Is(err, os.ErrNotExist) {
		if expectedHash != ([32]byte{}) {
			return File{}, nil, safepath.ErrChanged
		}
		return f, nil, nil
	}
	if err != nil {
		return File{}, nil, err
	}
	if sha256.Sum256(b) != expectedHash {
		return File{}, nil, safepath.ErrChanged
	}
	return f, b, nil
}

func encodeCatalog(f File) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// SaveIfUnchanged fails if an external writer changed or replaced the catalog
// after LoadForUpdate; it does not overwrite that writer's changes.
func (s *Store) SaveIfUnchanged(f File, expected []byte) error {
	if s == nil || s.dir == "" {
		return errors.New("profile store has no directory")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	b, err := encodeCatalog(f)
	if err != nil {
		return err
	}
	return safepath.CompareAndWrite(s.dir, "profiles.json", expected, b)
}

// RestoreSnapshotIfUnchanged restores the exact previous catalog after a
// failed operation, without replacing any intervening external edit.
func (s *Store) RestoreSnapshotIfUnchanged(written File, previous []byte) error {
	if s == nil || s.dir == "" || previous == nil {
		return errors.New("profile snapshot unavailable")
	}
	b, err := encodeCatalog(written)
	if err != nil {
		return err
	}
	return safepath.CompareAndWrite(s.dir, "profiles.json", b, previous)
}

func (s *Store) UpdateMetadata(uid, name, description string, options *CatalogOption) error {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" || len(name) > 256 || len(description) > 2048 {
		return errors.New("名称不能为空且不能超过 256 字节，描述不能超过 2048 字节")
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return err
	}
	for i := range f.Items {
		if f.Items[i].UID == uid {
			if f.Items[i].Option.VergeScriptApproval != nil && name != f.Items[i].Name {
				return errors.New("已启用的 Verge 脚本绑定订阅名称；请先关闭脚本，修改名称后重新预览并启用")
			}
			if err := retainScriptHistoryBeforeRename(&f.Items[i], name); err != nil {
				return err
			}
			if options != nil && f.Items[i].Type == "remote" {
				if options.UpdateInterval < 1 || options.UpdateInterval > 43200 {
					return errors.New("更新间隔必须在 1 到 43200 分钟之间")
				}
				if options.TimeoutSeconds < 1 || options.TimeoutSeconds > 300 {
					return errors.New("下载超时必须在 1 到 300 秒之间")
				}
				if len(options.UserAgent) > 512 || strings.ContainsAny(options.UserAgent, "\r\n") {
					return errors.New("用户代理无效或超过 512 字节")
				}
				old := &f.Items[i].Option
				old.AllowAutoUpdate, old.UpdateInterval = options.AllowAutoUpdate, options.UpdateInterval
				old.TimeoutSeconds, old.UserAgent = options.TimeoutSeconds, options.UserAgent
				old.UseClashProxy, old.UseSystemProxy, old.AcceptInvalid = options.UseClashProxy, options.UseSystemProxy, options.AcceptInvalid
			}
			f.Items[i].Name = name
			f.Items[i].Description = description
			return s.SaveIfUnchanged(f, snapshot)
		}
	}
	return errors.New("订阅不存在")
}

// SetCurrent marks uid as the active subscription.
func (s *Store) SetCurrent(uid string) error {
	if uid == "" {
		return errors.New("profile is empty")
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return err
	}
	found := false
	for _, it := range f.Items {
		if it.UID == uid {
			found = true
			break
		}
	}
	if !found {
		return errors.New("profile " + uid + " not found")
	}
	f.Current = uid
	return s.SaveIfUnchanged(f, snapshot)
}

// Delete removes an inactive profile from the catalog and its managed file.
// Active profiles must be switched first so the running kernel stays coherent.
func (s *Store) Delete(uid string) error {
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return err
	}
	if uid == "" || uid == f.Current {
		return errors.New("请先切换到其他订阅，再删除当前订阅")
	}
	idx := -1
	for i := range f.Items {
		if f.Items[i].UID == uid {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("订阅不存在")
	}
	rel := f.Items[idx].File
	if err := validateManagedProfilePath(rel); err != nil {
		return err
	}
	// A catalog imported from another application can contain multiple entries
	// for the same file. Never unlink data still referenced by another entry.
	shared, err := s.profileFileShared(f.Items, idx)
	if err != nil {
		return err
	}
	var removal *safepath.Removal
	if !shared {
		removal, err = safepath.PrepareRemoval(s.dir, rel)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if removal != nil {
		defer removal.Close()
	}
	f.Items = append(f.Items[:idx], f.Items[idx+1:]...)
	if err := s.SaveIfUnchanged(f, snapshot); err != nil {
		return err
	}
	if removal != nil {
		if err := removal.Remove(); err != nil {
			written, encodeErr := encodeCatalog(f)
			if encodeErr != nil {
				return errors.Join(err, encodeErr)
			}
			if restoreErr := safepath.CompareAndWrite(s.dir, "profiles.json", written, snapshot); restoreErr != nil {
				return errors.Join(err, errors.New("订阅文件删除失败，目录回滚也失败"), restoreErr)
			}
			return err
		}
	}
	return nil
}

func (s *Store) profileFileShared(items []CatalogItem, index int) (bool, error) {
	file := items[index].File
	var references []string
	for i, item := range items {
		if i != index && item.File != "" {
			references = append(references, item.File)
		}
		if previous := item.Option.VergeScriptPrevious; previous != nil && previous.Subscription != nil && previous.Subscription.File != "" {
			references = append(references, previous.Subscription.File)
		}
	}
	for _, reference := range references {
		if strings.EqualFold(filepath.Clean(reference), filepath.Clean(file)) {
			return true, nil
		}
	}
	if len(references) == 0 {
		return false, nil
	}
	target, err := safepath.OpenRead(s.dir, file)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer target.Close()
	targetInfo, err := target.Stat()
	if err != nil {
		return false, err
	}
	for _, reference := range references {
		if err := validateManagedProfilePath(reference); err != nil {
			return false, err
		}
		other, err := safepath.OpenRead(s.dir, reference)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		info, statErr := other.Stat()
		closeErr := other.Close()
		if statErr != nil {
			return false, statErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		if os.SameFile(targetInfo, info) {
			return true, nil
		}
	}
	return false, nil
}

// SharedProfileFile reports whether another catalog entry references the same
// managed path or underlying file. The caller must commit against this same
// catalog snapshot before relying on the result.
func (s *Store) SharedProfileFile(catalog File, uid string) (bool, error) {
	index := -1
	for i, item := range catalog.Items {
		if item.UID != uid {
			continue
		}
		if index >= 0 {
			return false, errors.New("duplicate profile id")
		}
		index = i
	}
	if index < 0 {
		return false, errors.New("profile not found")
	}
	if err := validateManagedProfilePath(catalog.Items[index].File); err != nil {
		return false, err
	}
	return s.profileFileShared(catalog.Items, index)
}

// DiscardFirstImport rolls back a failed first activation, without touching
// an existing catalog or any file outside the managed profiles directory.
func (s *Store) DiscardFirstImport(uid string) error {
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return err
	}
	if f.Current != uid {
		return errors.New("订阅目录已变化，无法自动回滚导入")
	}
	index := -1
	for i, item := range f.Items {
		if item.UID == uid {
			if index >= 0 {
				return errors.New("订阅目录已变化，无法自动回滚导入")
			}
			index = i
		}
	}
	if index < 0 {
		return errors.New("订阅目录已变化，无法自动回滚导入")
	}
	shared, err := s.profileFileShared(f.Items, index)
	if err != nil {
		return err
	}
	if shared {
		return errors.New("订阅文件仍被其他订阅引用，无法自动回滚导入")
	}
	rel := f.Items[index].File
	if err := validateManagedProfilePath(rel); err != nil {
		return err
	}
	removal, err := safepath.PrepareRemoval(s.dir, rel)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if removal != nil {
		defer removal.Close()
	}
	f.Current = ""
	f.Items = append(f.Items[:index], f.Items[index+1:]...)
	if err = s.SaveIfUnchanged(f, snapshot); err != nil {
		return err
	}
	if removal != nil {
		if err := removal.Remove(); err != nil {
			written, encodeErr := encodeCatalog(f)
			if encodeErr != nil {
				return errors.Join(err, encodeErr)
			}
			if restoreErr := safepath.CompareAndWrite(s.dir, "profiles.json", written, snapshot); restoreErr != nil {
				return errors.Join(err, errors.New("订阅文件删除失败，目录回滚也失败"), restoreErr)
			}
			return err
		}
	}
	return nil
}

func validateManagedProfilePath(relative string) error {
	if !filepath.IsLocal(relative) {
		return errors.New("订阅文件路径无效")
	}
	inside, err := filepath.Rel("profiles", relative)
	if err != nil || inside == "." || !filepath.IsLocal(inside) {
		return errors.New("订阅文件路径无效")
	}
	return nil
}

// RecordSelected stores group→node on the subscription uid. A second write
// for the same group replaces now instead of appending.
func (s *Store) RecordSelected(uid, group, node string) error {
	if group == "" || node == "" {
		return errors.New("selection is empty")
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return err
	}
	found := false
	for i := range f.Items {
		if f.Items[i].UID != uid {
			continue
		}
		found = true
		replaced := false
		for j := range f.Items[i].Selected {
			if f.Items[i].Selected[j].Name == group {
				f.Items[i].Selected[j].Now = node
				replaced = true
				break
			}
		}
		if !replaced {
			f.Items[i].Selected = append(f.Items[i].Selected, SelectedNode{Name: group, Now: node})
		}
	}
	if !found {
		return nil
	}
	return s.SaveIfUnchanged(f, snapshot)
}

// ErrInvalidURL is returned when a subscription link is not http(s).
var ErrInvalidURL = errors.New("无效的订阅链接，请输入以 http:// 或 https:// 开头的地址")

// ValidURL reports whether raw is an http or https URL with a host.
func ValidURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != "" && u.Opaque == ""
}

// ImportRemote fetches url, stores the body, and appends a remote item.
// The new item becomes current when the file had none.
func (s *Store) ImportRemote(raw string, fetch func(string) ([]byte, error)) (CatalogItem, error) {
	return s.ImportRemoteWithHeaders(raw, fetch, nil)
}

// ImportRemoteWithHeaders stores response traffic metadata with the profile.
func (s *Store) ImportRemoteWithHeaders(raw string, fetch func(string) ([]byte, error), headers http.Header) (CatalogItem, error) {
	item, _, err := s.ImportRemoteConfigured(raw, fetch, headers, nil)
	return item, err
}

// RemoteMetadata is committed with a new remote profile in the same catalog
// write. An empty name uses the subscription host.
type RemoteMetadata struct {
	Name        string
	Description string
	Option      CatalogOption
}

func ValidateRemoteMetadata(raw string, metadata RemoteMetadata) error {
	name := strings.TrimSpace(metadata.Name)
	if name == "" {
		name = hostOf(raw)
	}
	description := strings.TrimSpace(metadata.Description)
	if name == "" || len(name) > 256 || len(description) > 2048 || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsRune(description, '\x00') {
		return errors.New("名称或描述无效")
	}
	o := metadata.Option
	if o.UpdateInterval < 1 || o.UpdateInterval > 43200 || o.TimeoutSeconds < 1 || o.TimeoutSeconds > 300 || len(o.UserAgent) > 512 || strings.ContainsAny(o.UserAgent, "\r\n\x00") {
		return errors.New("订阅下载选项无效")
	}
	return nil
}

func (s *Store) ImportRemoteConfigured(raw string, fetch func(string) ([]byte, error), headers http.Header, metadata *RemoteMetadata) (CatalogItem, bool, error) {
	raw = strings.TrimSpace(raw)
	if !ValidURL(raw) {
		return CatalogItem{}, false, ErrInvalidURL
	}
	if fetch == nil {
		return CatalogItem{}, false, errors.New("no fetcher")
	}
	if metadata != nil {
		if err := ValidateRemoteMetadata(raw, *metadata); err != nil {
			return CatalogItem{}, false, err
		}
	}
	body, err := fetch(raw)
	if err != nil {
		return CatalogItem{}, false, err
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return CatalogItem{}, false, err
	}
	name := hostOf(raw)
	uid, rel, created, err := s.createProfileFile(f.Items, body)
	if err != nil {
		return CatalogItem{}, false, err
	}
	defer created.Close()
	item := CatalogItem{
		UID:     uid,
		Name:    name,
		URL:     raw,
		Type:    "remote",
		Updated: time.Now().UTC().Truncate(time.Second),
		File:    rel,
		Option:  CatalogOption{UpdateInterval: 1440, AllowAutoUpdate: true, TimeoutSeconds: 60},
	}
	if metadata != nil {
		if name := strings.TrimSpace(metadata.Name); name != "" {
			item.Name = name
		}
		item.Description = strings.TrimSpace(metadata.Description)
		item.Option = metadata.Option
		item.Option.UserAgent = strings.TrimSpace(item.Option.UserAgent)
	}
	ApplySubscriptionUserInfo(&item, headers)
	f.Items = append(f.Items, item)
	first := f.Current == ""
	if first {
		f.Current = uid
	}
	if err := s.SaveIfUnchanged(f, snapshot); err != nil {
		return CatalogItem{}, false, errors.Join(err, created.Remove())
	}
	return item, first, nil
}

// ImportLocal stores a YAML file dropped on the window.
func (s *Store) ImportLocal(filename string, body []byte) (CatalogItem, error) {
	item, _, err := s.ImportLocalWithState(filename, body)
	return item, err
}

func (s *Store) ImportLocalWithState(filename string, body []byte) (CatalogItem, bool, error) {
	if !strings.HasSuffix(strings.ToLower(filename), ".yaml") && !strings.HasSuffix(strings.ToLower(filename), ".yml") {
		return CatalogItem{}, false, errors.New("仅支持 YAML 文件")
	}
	f, snapshot, err := s.LoadForUpdate()
	if err != nil {
		return CatalogItem{}, false, err
	}
	name := filename
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "New Profile"
	}
	uid, rel, created, err := s.createProfileFile(f.Items, body)
	if err != nil {
		return CatalogItem{}, false, err
	}
	defer created.Close()
	item := CatalogItem{UID: uid, Name: name, Type: "local", File: rel, Updated: time.Now().UTC().Truncate(time.Second)}
	f.Items = append(f.Items, item)
	first := f.Current == ""
	if first {
		f.Current = uid
	}
	if err := s.SaveIfUnchanged(f, snapshot); err != nil {
		return CatalogItem{}, false, errors.Join(err, created.Remove())
	}
	return item, first, nil
}

func (s *Store) createProfileFile(items []CatalogItem, body []byte) (string, string, *safepath.Created, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return "", "", nil, err
	}
	taken := make(map[string]bool, len(items))
	for _, item := range items {
		taken[item.UID] = true
	}
	for n := len(items) + 1; ; n++ {
		id := "p" + itoa(n)
		if taken[id] {
			continue
		}
		rel := filepath.Join("profiles", id+".yaml")
		created, err := safepath.CreateExclusive(s.dir, rel, body, true)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", "", nil, err
		}
		return id, rel, created, nil
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "订阅"
	}
	return u.Host
}

// SafeDisplayName hides credentials or query parameters accidentally included
// by older versions when deriving a default name from a subscription URL.
// Explicit names are preserved, even when users put sensitive data in them.
func SafeDisplayName(item CatalogItem) string {
	if item.URL == "" {
		return item.Name
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(item.URL), "https://"), "http://")
	legacy, _, _ := strings.Cut(rest, "/")
	if item.Name == legacy {
		return hostOf(item.URL)
	}
	return item.Name
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
