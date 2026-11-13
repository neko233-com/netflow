package profile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	UpdateInterval  int    `json:"update_interval,omitempty"`
	UseSystemProxy  bool   `json:"use_system_proxy,omitempty"`
	UseClashProxy   bool   `json:"use_clash_proxy,omitempty"`
	AcceptInvalid   bool   `json:"allow_insecure,omitempty"`
	AllowAutoUpdate bool   `json:"allow_auto_update,omitempty"`
	Rules           string `json:"rules,omitempty"`
	Proxies         string `json:"proxies,omitempty"`
	Groups          string `json:"groups,omitempty"`
	Merge           string `json:"merge,omitempty"`
	Script          string `json:"script,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	TimeoutSeconds  int    `json:"timeout,omitempty"`
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

func (s *Store) path() string { return filepath.Join(s.dir, "profiles.json") }

// Load returns an empty file when profiles.json is missing.
func (s *Store) Load() (File, error) {
	if s == nil || s.dir == "" {
		return File{}, errors.New("profile store has no directory")
	}
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return File{}, nil
	}
	if err != nil {
		return File{}, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return File{}, nil
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, err
	}
	return f, nil
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
	file, err := os.CreateTemp(s.dir, ".profiles-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(b)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, s.path())
}

func (s *Store) UpdateMetadata(uid, name, description string, options *CatalogOption) error {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" || len(name) > 256 || len(description) > 2048 {
		return errors.New("名称不能为空且不能超过 256 字节，描述不能超过 2048 字节")
	}
	f, err := s.Load()
	if err != nil {
		return err
	}
	for i := range f.Items {
		if f.Items[i].UID == uid {
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
				if options.UseSystemProxy && !options.UseClashProxy {
					return errors.New("此版本尚不支持订阅使用系统代理，请改用内核代理")
				}
				old := &f.Items[i].Option
				old.AllowAutoUpdate, old.UpdateInterval = options.AllowAutoUpdate, options.UpdateInterval
				old.TimeoutSeconds, old.UserAgent = options.TimeoutSeconds, options.UserAgent
				old.UseClashProxy, old.UseSystemProxy, old.AcceptInvalid = options.UseClashProxy, options.UseSystemProxy, options.AcceptInvalid
			}
			f.Items[i].Name = name
			f.Items[i].Description = description
			return s.Save(f)
		}
	}
	return errors.New("订阅不存在")
}

// SetCurrent marks uid as the active subscription.
func (s *Store) SetCurrent(uid string) error {
	if uid == "" {
		return errors.New("profile is empty")
	}
	f, err := s.Load()
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
	return s.Save(f)
}

// Delete removes an inactive profile from the catalog and its managed file.
// Active profiles must be switched first so the running kernel stays coherent.
func (s *Store) Delete(uid string) error {
	f, err := s.Load()
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
	managed := filepath.Join(s.dir, "profiles")
	abs := filepath.Join(s.dir, rel)
	inside, err := filepath.Rel(managed, abs)
	if rel == "" || err != nil || inside == "." || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
		return errors.New("订阅文件路径无效")
	}
	f.Items = append(f.Items[:idx], f.Items[idx+1:]...)
	if err := s.Save(f); err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// DiscardFirstImport rolls back a failed first activation, without touching
// an existing catalog or any file outside the managed profiles directory.
func (s *Store) DiscardFirstImport(uid string) error {
	f, err := s.Load()
	if err != nil {
		return err
	}
	if len(f.Items) != 1 || f.Current != uid || f.Items[0].UID != uid {
		return errors.New("订阅目录已变化，无法自动回滚导入")
	}
	rel := f.Items[0].File
	abs := filepath.Join(s.dir, rel)
	inside, err := filepath.Rel(filepath.Join(s.dir, "profiles"), abs)
	if rel == "" || err != nil || inside == "." || inside == ".." || filepath.IsAbs(inside) || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return errors.New("订阅文件路径无效")
	}
	if err = s.Save(File{}); err != nil {
		return err
	}
	if err = os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RecordSelected stores group→node on the subscription uid. A second write
// for the same group replaces now instead of appending.
func (s *Store) RecordSelected(uid, group, node string) error {
	if group == "" || node == "" {
		return errors.New("selection is empty")
	}
	f, err := s.Load()
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
	return s.Save(f)
}

// ErrInvalidURL is returned when a subscription link is not http(s).
var ErrInvalidURL = errors.New("无效的订阅链接，请输入以 http:// 或 https:// 开头的地址")

// ValidURL reports whether raw is an http or https URL with a host.
func ValidURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	host, _, _ := strings.Cut(rest, "/")
	return host != "" && !strings.Contains(host, " ")
}

// ImportRemote fetches url, stores the body, and appends a remote item.
// The new item becomes current when the file had none.
func (s *Store) ImportRemote(raw string, fetch func(string) ([]byte, error)) (CatalogItem, error) {
	raw = strings.TrimSpace(raw)
	if !ValidURL(raw) {
		return CatalogItem{}, ErrInvalidURL
	}
	if fetch == nil {
		return CatalogItem{}, errors.New("no fetcher")
	}
	body, err := fetch(raw)
	if err != nil {
		return CatalogItem{}, err
	}
	f, err := s.Load()
	if err != nil {
		return CatalogItem{}, err
	}
	name := hostOf(raw)
	uid, rel, err := s.createProfileFile(f.Items, body)
	if err != nil {
		return CatalogItem{}, err
	}
	item := CatalogItem{
		UID:     uid,
		Name:    name,
		URL:     raw,
		Type:    "remote",
		Updated: time.Now().UTC().Truncate(time.Second),
		File:    rel,
		Option:  CatalogOption{UpdateInterval: 1440, AllowAutoUpdate: true, TimeoutSeconds: 60},
	}
	f.Items = append(f.Items, item)
	if f.Current == "" {
		f.Current = uid
	}
	if err := s.Save(f); err != nil {
		_ = os.Remove(filepath.Join(s.dir, rel))
		return CatalogItem{}, err
	}
	return item, nil
}

// ImportLocal stores a YAML file dropped on the window.
func (s *Store) ImportLocal(filename string, body []byte) (CatalogItem, error) {
	if !strings.HasSuffix(strings.ToLower(filename), ".yaml") && !strings.HasSuffix(strings.ToLower(filename), ".yml") {
		return CatalogItem{}, errors.New("仅支持 YAML 文件")
	}
	f, err := s.Load()
	if err != nil {
		return CatalogItem{}, err
	}
	name := filename
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "New Profile"
	}
	uid, rel, err := s.createProfileFile(f.Items, body)
	if err != nil {
		return CatalogItem{}, err
	}
	item := CatalogItem{UID: uid, Name: name, Type: "local", File: rel, Updated: time.Now().UTC().Truncate(time.Second)}
	f.Items = append(f.Items, item)
	if f.Current == "" {
		f.Current = uid
	}
	if err := s.Save(f); err != nil {
		_ = os.Remove(filepath.Join(s.dir, rel))
		return CatalogItem{}, err
	}
	return item, nil
}

func (s *Store) createProfileFile(items []CatalogItem, body []byte) (string, string, error) {
	dir := filepath.Join(s.dir, "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
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
		path := filepath.Join(s.dir, rel)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		if _, err = file.Write(body); err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
			return "", "", err
		}
		return id, rel, nil
	}
}

func hostOf(raw string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	host, _, _ := strings.Cut(rest, "/")
	if host == "" {
		return "订阅"
	}
	return host
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
