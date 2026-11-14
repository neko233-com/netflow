package migration

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/safepath"
	"go.yaml.in/yaml/v3"
)

type ImportResult struct {
	Imported      int      `json:"imported"`
	ActiveProfile string   `json:"active_profile,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "v" + hex.EncodeToString(b[:]), nil
}
func writeNew(root *os.Root, path string, body []byte) error {
	f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = root.Remove(path)
	}
	return err
}
func validProfile(body []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return errors.New("订阅 YAML 无效")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("订阅必须是 YAML 映射")
	}
	return nil
}

func (s *Source) ruleLayer(id string) (rewrite.Layer, error) {
	for _, child := range s.index.Items {
		if child.UID != id || child.Type != "rules" {
			continue
		}
		var rules struct {
			Prepend []string `yaml:"prepend"`
			Append  []string `yaml:"append"`
			Delete  []string `yaml:"delete"`
		}
		if err := yaml.Unmarshal(s.files["profiles/"+child.File], &rules); err != nil {
			return rewrite.Layer{}, errors.New("规则扩展格式无效")
		}
		layer := rewrite.Layer{Prepend: rules.Prepend, Append: rules.Append, Remove: rules.Delete}
		if err := layer.Validate(); err != nil {
			return rewrite.Layer{}, fmt.Errorf("规则扩展无效: %w", err)
		}
		return layer, nil
	}
	return rewrite.Layer{}, errors.New("规则扩展引用无效")
}

// ImportVerge merges imported profiles into a stopped NetFlow data directory.
// Callers must hold appdir.Acquire(target) to prevent concurrent changes.
// Files are staged under new random names; on failure existing profiles are retained.
func (s *Source) ValidateTarget(target string) error {
	if s == nil || target == "" || !filepath.IsAbs(target) {
		return errors.New("目标目录必须是绝对路径")
	}
	if s.originDir != "" {
		paths := []string{filepath.Clean(target)}
		probe := filepath.Clean(target)
		var suffix []string
		for {
			if resolved, err := safepath.Canonical(probe); err == nil {
				for i := len(suffix) - 1; i >= 0; i-- {
					resolved = filepath.Join(resolved, suffix[i])
				}
				paths = append(paths, resolved)
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			parent := filepath.Dir(probe)
			if parent == probe {
				return errors.New("无法解析目标目录")
			}
			suffix = append(suffix, filepath.Base(probe))
			probe = parent
		}
		for _, p := range paths {
			rel, err := filepath.Rel(s.originDir, p)
			if err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return errors.New("目标目录不能位于 Verge 源目录内")
			}
		}
	}
	return nil
}

func safeTargetDir(target, name string) error {
	path := filepath.Join(target, name)
	if info, err := os.Lstat(path); err == nil && !info.IsDir() {
		return errors.New("目标子目录必须是普通目录，不能是链接或重解析点")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0700)
}

func (s *Source) ImportVerge(target string) (ImportResult, error) {
	if err := s.ValidateTarget(target); err != nil {
		return ImportResult{}, err
	}
	catalogStore := profile.NewStore(target)
	catalog, err := catalogStore.Load()
	if err != nil {
		return ImportResult{}, err
	}
	if err = safeTargetDir(target, "profiles"); err != nil {
		return ImportResult{}, err
	}
	if err = safeTargetDir(target, "verge-imports"); err != nil {
		return ImportResult{}, err
	}
	if err = safeTargetDir(target, "verge-providers"); err != nil {
		return ImportResult{}, err
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return ImportResult{}, err
	}
	defer root.Close()
	var providerCreated []string
	var providerDir string
	var created []string
	committed := false
	defer func() {
		if !committed {
			for _, p := range providerCreated {
				_ = root.Remove(filepath.FromSlash(p))
			}
			if providerDir != "" {
				_ = root.Remove(filepath.FromSlash(providerDir))
			}
			for _, p := range created {
				_ = root.Remove(p)
			}
		}
	}()
	archiveID, err := randomID()
	if err != nil {
		return ImportResult{}, err
	}
	providerPaths := map[string]string{}
	for raw, data := range s.providers {
		if providerDir == "" {
			providerDir = "verge-providers/" + archiveID
			if err := root.Mkdir(filepath.FromSlash(providerDir), 0700); err != nil {
				providerDir = ""
				return ImportResult{}, err
			}
		}
		hash := sha256.Sum256([]byte(raw))
		rel := providerDir + "/" + hex.EncodeToString(hash[:])
		if data.present {
			f, e := root.OpenFile(filepath.FromSlash(rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return ImportResult{}, e
			}
			providerCreated = append(providerCreated, rel)
			_, e = f.Write(data.data)
			if e == nil {
				e = f.Sync()
			}
			if closeErr := f.Close(); e == nil {
				e = closeErr
			}
			if e != nil {
				return ImportResult{}, e
			}
		}
		providerPaths[raw] = rel
	}
	archiveRel := filepath.Join("verge-imports", archiveID+".zip")
	if err = s.writeSourceArchive(root, archiveRel); err != nil {
		return ImportResult{}, err
	}
	created = append(created, archiveRel)
	mapped := map[string]string{}
	var result ImportResult
	result.Warnings = append(result.Warnings, s.Preview().Warnings...)
	for _, v := range s.index.Items {
		if v.Type != "remote" && v.Type != "local" {
			continue
		}
		body := s.files["profiles/"+v.File]
		if err = validProfile(body); err != nil {
			return ImportResult{}, fmt.Errorf("订阅数据无效: %w", err)
		}
		id, e := randomID()
		if e != nil {
			return ImportResult{}, e
		}
		rel := filepath.Join("profiles", id+".yaml")
		if err = writeNew(root, rel, body); err != nil {
			return ImportResult{}, err
		}
		created = append(created, rel)
		mapped[v.UID] = id
		item := profile.CatalogItem{UID: id, Type: v.Type, Name: v.Name, Description: v.Desc, URL: v.URL, Home: v.Home, File: rel, Option: profile.CatalogOption{UpdateInterval: v.Option.UpdateInterval, AllowAutoUpdate: v.Option.AllowAutoUpdate, UseSystemProxy: v.Option.WithProxy, UseClashProxy: v.Option.SelfProxy, UserAgent: v.Option.UserAgent, TimeoutSeconds: v.Option.Timeout, VergeArchive: archiveRel, VergeUID: v.UID}}
		for _, ref := range s.profileProviders[v.UID] {
			if destination, ok := providerPaths[ref.Path]; ok {
				if item.Option.VergeProviderPaths == nil {
					item.Option.VergeProviderPaths = map[string]string{}
				}
				item.Option.VergeProviderPaths[ref.Path] = destination
			}
		}
		ext, e := s.extensions(v.UID)
		if e != nil {
			return ImportResult{}, e
		}
		ext.Rules, e = s.selectedRuleData(v.UID)
		if e != nil {
			return ImportResult{}, e
		}
		item.Option.VergeRulesBeforeScripts = true
		item.Option.VergeExtensions = hasExtensions(ext)
		if item.Name == "" {
			item.Name = "迁入订阅"
		}
		if item.Option.UpdateInterval <= 0 || item.Option.UpdateInterval > 43200 {
			item.Option.UpdateInterval = 1440
		}
		if item.Option.TimeoutSeconds <= 0 || item.Option.TimeoutSeconds > 300 {
			item.Option.TimeoutSeconds = 20
		}
		if v.Updated > 0 && v.Updated <= 253402300799 {
			item.Updated = time.Unix(v.Updated, 0).UTC()
		}
		used := v.Extra.Upload
		if math.MaxUint64-used < v.Extra.Download {
			used = math.MaxUint64
		} else {
			used += v.Extra.Download
		}
		if used > math.MaxInt64 {
			used = math.MaxInt64
		}
		total := v.Extra.Total
		if total > math.MaxInt64 {
			total = math.MaxInt64
		}
		item.Used = int64(used)
		item.Total = int64(total)
		if v.Extra.Expire > 0 && v.Extra.Expire <= 253402300799 {
			item.Expire = time.Unix(int64(v.Extra.Expire), 0).UTC()
		}
		for _, sel := range v.Selected {
			if sel.Name != "" && sel.Now != "" {
				item.Selected = append(item.Selected, profile.SelectedNode{Name: sel.Name, Now: sel.Now})
			}
		}
		if s.dnsFlags[v.UID] && (len(s.dns) > 0 || len(s.dnsHosts) > 0) {
			if _, e := profile.ComposeVergeDNS(body, string(s.dns), string(s.dnsHosts)); e != nil {
				return ImportResult{}, fmt.Errorf("DNS 覆写无效: %w", e)
			}
			item.Option.DNSEnabled = true
			item.Option.DNSOverride = string(s.dns)
			item.Option.DNSVergeMerge = true
			item.Option.DNSVergeHosts = string(s.dnsHosts)
		}
		catalog.Items = append(catalog.Items, item)
		result.Imported++
	}
	if result.Imported == 0 {
		return ImportResult{}, errors.New("没有可迁入的订阅")
	}
	if catalog.Current == "" {
		catalog.Current = mapped[s.index.Current]
		if catalog.Current == "" {
			for _, v := range s.index.Items {
				if id := mapped[v.UID]; id != "" {
					catalog.Current = id
					break
				}
			}
		}
	}
	result.ActiveProfile = catalog.Current
	if err = catalogStore.Save(catalog); err != nil {
		return ImportResult{}, err
	}
	committed = true
	return result, nil
}

func (s *Source) writeSourceArchive(root *os.Root, path string) error {
	f, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	flags := map[string]map[string]bool{}
	for id, enabled := range s.dnsFlags {
		flags[id] = map[string]bool{"enabled": enabled}
	}
	sanitized, err := yaml.Marshal(map[string]any{"profile_dns_settings": flags})
	if err == nil {
		var w io.Writer
		w, err = zw.Create("verge.yaml")
		if err == nil {
			_, err = w.Write(sanitized)
		}
	}
	for _, name := range []string{"profiles.yaml", "dns_config.yaml"} {
		if b, ok := s.files[name]; ok {
			w, e := zw.Create(name)
			if e != nil {
				err = e
				break
			}
			if _, e = w.Write(b); e != nil {
				err = e
				break
			}
		}
	}
	if err == nil {
		seen := map[string]bool{}
		for _, item := range s.index.Items {
			name := "profiles/" + item.File
			if seen[name] {
				continue
			}
			seen[name] = true
			w, e := zw.Create(name)
			if e != nil {
				err = e
				break
			}
			if _, e = w.Write(s.files[name]); e != nil {
				err = e
				break
			}
		}
		if data, ok := s.files["profiles/Merge.yaml"]; err == nil && ok && !seen["profiles/Merge.yaml"] {
			w, e := zw.Create("profiles/Merge.yaml")
			if e != nil {
				err = e
			} else if _, e = w.Write(data); e != nil {
				err = e
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
		_ = root.Remove(path)
	}
	return err
}
