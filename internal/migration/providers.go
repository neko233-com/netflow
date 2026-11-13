package migration

import (
	"archive/zip"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/neko233-com/netflow/internal/profile"
)

type providerSource struct {
	rel     string
	data    []byte
	present bool
}

// providerRelative permits only paths within the explicitly selected source.
// In particular ZIPs cannot use absolute paths or platform-specific drives.
func providerRelative(raw, root string) string {
	if len(raw) > 4096 || strings.ContainsRune(raw, 0) {
		return ""
	}
	p := filepath.FromSlash(strings.ReplaceAll(raw, `\`, "/"))
	if filepath.IsAbs(p) {
		if root == "" {
			return ""
		}
		var err error
		p, err = filepath.Rel(root, p)
		if err != nil {
			return ""
		}
	}
	if !filepath.IsLocal(p) || strings.Contains(p, ":") {
		return ""
	}
	rel := filepath.ToSlash(filepath.Clean(p))
	if rel == "." || path.Clean(rel) != rel {
		return ""
	}
	return rel
}

func (s *Source) readProviders(source string) error {
	s.providers = map[string]providerSource{}
	s.profileProviders = map[string][]profile.VergeProvider{}
	s.providerWarnings = map[string]bool{}
	for _, item := range s.index.Items {
		if item.Type != "local" && item.Type != "remote" {
			continue
		}
		body := s.files["profiles/"+item.File]
		ext, err := s.extensions(item.UID)
		if err != nil {
			return err
		}
		if hasExtensions(ext) {
			body, err = profile.ComposeVergeExtensions(body, ext)
			if err != nil {
				return err
			}
		}
		refs, err := profile.VergeProviders(body)
		if err != nil {
			return err
		}
		if len(refs) > 4096 {
			return errors.New("规则或代理集合过多")
		}
		s.profileProviders[item.UID] = refs
		for _, ref := range refs {
			if ref.Path == "" {
				continue
			}
			if _, ok := s.providers[ref.Path]; !ok {
				s.providers[ref.Path] = providerSource{rel: providerRelative(ref.Path, s.originDir)}
			}
		}
	}
	if len(s.providers) > 4096 {
		return errors.New("规则或代理集合过多")
	}
	var root *os.Root
	var zr *zip.ReadCloser
	var err error
	entries := map[string]*zip.File{}
	if s.originDir != "" {
		root, err = os.OpenRoot(s.originDir)
		if err != nil {
			return err
		}
		defer root.Close()
	} else {
		zr, err = zip.OpenReader(source)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, entry := range zr.File {
			if entry.FileInfo().IsDir() {
				continue
			}
			key := strings.ToLower(entry.Name)
			if _, ok := entries[key]; ok {
				return errors.New("备份包含重名文件")
			}
			entries[key] = entry
		}
	}
	total := 0
	for _, b := range s.files {
		total += len(b)
	}
	cache := map[string]providerSource{}
	for raw, ref := range s.providers {
		if ref.rel == "" {
			continue
		}
		key := ref.rel
		if root == nil || runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if prev, ok := cache[key]; ok {
			s.providers[raw] = prev
			continue
		}
		var data []byte
		if root != nil {
			f, e := root.Open(filepath.FromSlash(ref.rel))
			if e == nil {
				info, statErr := f.Stat()
				if statErr == nil && info.Mode().IsRegular() {
					data, e = readBounded(f, maxEntry)
				} else {
					e = errors.New("集合不是普通文件")
				}
				_ = f.Close()
				if e != nil {
					return e
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				// An inaccessible or escaping link is never followed; report it as missing.
				data = nil
			}
		} else if entry := entries[key]; entry != nil && entry.Mode().IsRegular() {
			f, e := entry.Open()
			if e != nil {
				return e
			}
			data, e = readBounded(f, maxEntry)
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		}
		if data != nil {
			total += len(data)
			if total > maxTotal {
				return errors.New("迁移数据过大")
			}
			ref.data, ref.present = data, true
		}
		cache[key], s.providers[raw] = ref, ref
	}
	for _, refs := range s.profileProviders {
		for _, ref := range refs {
			if !s.providers[ref.Path].present {
				if ref.Type == "file" {
					s.providerWarnings["文件型规则或代理集合的外部文件未迁入，可能需要重新下载或修正路径"] = true
				} else {
					s.providerWarnings["HTTP 集合缓存未迁入，将在使用时重新下载"] = true
				}
			}
		}
	}
	return nil
}
