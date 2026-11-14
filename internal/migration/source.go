// Package migration handles explicit Clash Verge Rev import and export.
package migration

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/safepath"
	"go.yaml.in/yaml/v3"
)

const maxEntry = 8 << 20
const maxTotal = 64 << 20

type vergeIndex struct {
	Current string      `yaml:"current"`
	Items   []vergeItem `yaml:"items"`
}
type vergeSelection struct {
	Name string `yaml:"name,omitempty"`
	Now  string `yaml:"now,omitempty"`
}
type vergeExtra struct {
	Upload   uint64 `yaml:"upload,omitempty"`
	Download uint64 `yaml:"download,omitempty"`
	Total    uint64 `yaml:"total,omitempty"`
	Expire   uint64 `yaml:"expire,omitempty"`
}
type vergeOption struct {
	UpdateInterval  int    `yaml:"update_interval,omitempty"`
	AllowAutoUpdate bool   `yaml:"allow_auto_update,omitempty"`
	WithProxy       bool   `yaml:"with_proxy,omitempty"`
	SelfProxy       bool   `yaml:"self_proxy,omitempty"`
	UserAgent       string `yaml:"user_agent,omitempty"`
	Timeout         int    `yaml:"timeout,omitempty"`
	Rules           string `yaml:"rules,omitempty"`
	Proxies         string `yaml:"proxies,omitempty"`
	Groups          string `yaml:"groups,omitempty"`
	Merge           string `yaml:"merge,omitempty"`
	Script          string `yaml:"script,omitempty"`
}
type vergeItem struct {
	UID      string           `yaml:"uid,omitempty"`
	Type     string           `yaml:"type,omitempty"`
	Name     string           `yaml:"name,omitempty"`
	Desc     string           `yaml:"desc,omitempty"`
	URL      string           `yaml:"url,omitempty"`
	Home     string           `yaml:"home,omitempty"`
	File     string           `yaml:"file,omitempty"`
	Updated  int64            `yaml:"updated,omitempty"`
	Extra    vergeExtra       `yaml:"extra,omitempty"`
	Selected []vergeSelection `yaml:"selected,omitempty"`
	Option   vergeOption      `yaml:"option,omitempty"`
}
type Source struct {
	index            vergeIndex
	files            map[string][]byte
	dns              []byte
	dnsFlags         map[string]bool
	dnsHosts         []byte
	originDir        string
	itemByID         map[string]int
	providers        map[string]providerSource
	profileProviders map[string][]profile.VergeProvider
	providerWarnings map[string]bool
}

type PreviewProfile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Active bool   `json:"active"`
}
type Preview struct {
	Profiles []PreviewProfile `json:"profiles"`
	Warnings []string         `json:"warnings,omitempty"`
}

func safeFilename(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\:\x00") && filepath.Base(s) == s && path.Base(s) == s
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("迁移文件过大")
	}
	return b, nil
}

func marshalResolved(node *yaml.Node) ([]byte, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	resolved, err := profile.MaterializeYAMLNode(node)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(resolved)
}

// ReadVerge accepts an application data directory or a Verge backup ZIP.
// It reads only recognized regular files, never extracts archive paths.
func ReadVerge(source string) (*Source, error) {
	st, err := os.Stat(source)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	originDir := ""
	if st.IsDir() {
		root, err := safepath.Canonical(source)
		if err != nil {
			return nil, err
		}
		originDir, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		safeRoot, err := os.OpenRoot(root)
		if err != nil {
			return nil, err
		}
		defer safeRoot.Close()
		read := func(rel string, required bool) error {
			f, e := safeRoot.Open(filepath.FromSlash(rel))
			if errors.Is(e, os.ErrNotExist) && !required {
				return nil
			}
			if e != nil {
				return e
			}
			defer f.Close()
			info, e := f.Stat()
			if e != nil || !info.Mode().IsRegular() {
				return errors.New("迁移源包含非普通文件")
			}
			b, e := readBounded(f, maxEntry)
			if e != nil {
				return e
			}
			files[rel] = b
			return nil
		}
		if err = read("profiles.yaml", true); err != nil {
			return nil, err
		}
		for _, name := range []string{"verge.yaml", "config.yaml", "dns_config.yaml", "profiles/Merge.yaml"} {
			if err = read(name, false); err != nil {
				return nil, err
			}
		}
		var idx vergeIndex
		if err = yaml.Unmarshal(files["profiles.yaml"], &idx); err != nil {
			return nil, fmt.Errorf("profiles.yaml 无效: %w", err)
		}
		if len(idx.Items) > 5000 {
			return nil, errors.New("订阅条目过多")
		}
		total := len(files["profiles/Merge.yaml"])
		for _, item := range idx.Items {
			if !safeFilename(item.File) {
				return nil, errors.New("订阅文件名无效")
			}
			rel := "profiles/" + item.File
			if _, ok := files[rel]; !ok {
				if err = read(rel, true); err != nil {
					return nil, err
				}
				total += len(files[rel])
				if total > maxTotal {
					return nil, errors.New("迁移数据过大")
				}
			}
		}
		original := files["profiles.yaml"]
		if err = read("profiles.yaml", true); err != nil {
			return nil, err
		}
		if !bytes.Equal(original, files["profiles.yaml"]) {
			return nil, errors.New("Verge 配置在读取时发生变化，请重试")
		}
	} else {
		zr, err := zip.OpenReader(source)
		if err != nil {
			return nil, fmt.Errorf("无法打开 Verge 备份: %w", err)
		}
		defer zr.Close()
		total := int64(0)
		for _, entry := range zr.File {
			n := entry.Name
			if entry.FileInfo().IsDir() {
				continue
			}
			if strings.Contains(n, `\`) || strings.HasPrefix(n, "/") || path.Clean(n) != n || n == ".." || strings.HasPrefix(n, "../") || entry.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("备份包含不安全的路径")
			}
			allowed := n == "profiles.yaml" || n == "verge.yaml" || n == "config.yaml" || n == "dns_config.yaml" || strings.HasPrefix(n, "profiles/") && safeFilename(strings.TrimPrefix(n, "profiles/"))
			if !allowed {
				continue
			}
			if _, exists := files[n]; exists {
				return nil, errors.New("备份包含重复文件")
			}
			if entry.UncompressedSize64 > maxEntry {
				return nil, errors.New("备份文件过大")
			}
			total += int64(entry.UncompressedSize64)
			if total > maxTotal {
				return nil, errors.New("备份数据过大")
			}
			f, e := entry.Open()
			if e != nil {
				return nil, e
			}
			b, e := readBounded(f, maxEntry)
			closeErr := f.Close()
			if e != nil {
				return nil, e
			}
			if closeErr != nil {
				return nil, closeErr
			}
			files[n] = b
		}
		if _, ok := files["profiles.yaml"]; !ok {
			return nil, errors.New("备份缺少 profiles.yaml")
		}
	}
	var idx vergeIndex
	if err := yaml.Unmarshal(files["profiles.yaml"], &idx); err != nil {
		return nil, fmt.Errorf("profiles.yaml 无效: %w", err)
	}
	if len(idx.Items) > 5000 {
		return nil, errors.New("订阅条目过多")
	}
	seen := map[string]bool{}
	itemByID := make(map[string]int, len(idx.Items))
	for i, item := range idx.Items {
		if item.UID == "" || len(item.UID) > 128 || seen[item.UID] {
			return nil, errors.New("订阅标识缺失或重复")
		}
		seen[item.UID] = true
		itemByID[item.UID] = i
		if !safeFilename(item.File) {
			return nil, errors.New("订阅文件名无效")
		}
		if _, ok := files["profiles/"+item.File]; !ok {
			return nil, errors.New("备份缺少引用的订阅文件")
		}
	}
	s := &Source{index: idx, files: files, dnsFlags: map[string]bool{}, originDir: originDir, itemByID: itemByID}
	if b := files["verge.yaml"]; len(b) > 0 {
		var v struct {
			ProfileDNS map[string]struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"profile_dns_settings"`
		}
		if err := yaml.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("verge.yaml 无效: %w", err)
		}
		for id, entry := range v.ProfileDNS {
			s.dnsFlags[id] = entry.Enabled
		}
	}
	if b := files["dns_config.yaml"]; len(b) > 0 {
		var d yaml.Node
		if err := yaml.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("dns_config.yaml 无效: %w", err)
		}
		if len(d.Content) != 1 || d.Content[0].Kind != yaml.MappingNode {
			return nil, errors.New("dns_config.yaml 必须是 YAML 映射")
		}
		root := d.Content[0]
		legacy := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		var dns *yaml.Node
		for i := 0; i+1 < len(root.Content); i += 2 {
			key, value := root.Content[i], root.Content[i+1]
			switch key.Value {
			case "dns":
				dns = value
			case "hosts":
				if value.Kind == yaml.AliasNode {
					value = value.Alias
				}
				if value != nil && value.Kind == yaml.MappingNode && len(value.Content) > 0 {
					s.dnsHosts, err = marshalResolved(value)
					if err != nil {
						return nil, err
					}
				}
			default:
				legacy.Content = append(legacy.Content, key, value)
			}
		}
		if dns == nil && len(legacy.Content) > 0 {
			dns = legacy
		}
		if dns != nil && dns.Kind == yaml.AliasNode {
			dns = dns.Alias
		}
		if dns != nil && dns.Kind == yaml.MappingNode {
			s.dns, err = marshalResolved(dns)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, item := range s.index.Items {
		if item.Type != "remote" && item.Type != "local" {
			continue
		}
		if len(item.Name) > 256 || len(item.Desc) > 2048 || len(item.URL) > 8192 || len(item.Home) > 8192 || len(item.Selected) > 1000 {
			return nil, errors.New("订阅元数据超出长度限制")
		}
		for _, sel := range item.Selected {
			if len(sel.Name) > 1024 || len(sel.Now) > 1024 {
				return nil, errors.New("节点选择记录过长")
			}
		}
		body := s.files["profiles/"+item.File]
		if err := validProfile(body); err != nil {
			return nil, fmt.Errorf("订阅数据无效: %w", err)
		}
		ext, err := s.extensions(item.UID)
		if err != nil {
			return nil, err
		}
		if hasExtensions(ext) {
			body, err = profile.ComposeVergeExtensions(body, ext)
			if err != nil {
				return nil, fmt.Errorf("Verge 扩展无效: %w", err)
			}
		}
		if s.dnsFlags[item.UID] && (len(s.dns) > 0 || len(s.dnsHosts) > 0) {
			if _, err := profile.ComposeVergeDNS(body, string(s.dns), string(s.dnsHosts)); err != nil {
				return nil, fmt.Errorf("DNS 覆写无效: %w", err)
			}
		}
		if item.Option.Rules != "" {
			if _, err := s.ruleLayer(item.Option.Rules); err != nil {
				return nil, err
			}
		}
	}
	if err := s.readProviders(source); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Source) Preview() Preview {
	var out Preview
	unsupported := map[string]bool{}
	for _, item := range s.index.Items {
		if item.Type != "remote" && item.Type != "local" {
			continue
		}
		out.Profiles = append(out.Profiles, PreviewProfile{ID: item.UID, Name: item.Name, Type: item.Type, Active: item.UID == s.index.Current})
		if item.Option.Script != "" {
			unsupported["脚本扩展会保留，但不会自动执行"] = true
		}
		for _, ref := range []struct{ id, kind string }{{item.Option.Proxies, "proxies"}, {item.Option.Groups, "groups"}, {item.Option.Merge, "merge"}} {
			if ref.id != "" {
				if i, ok := s.itemByID[ref.id]; !ok || s.index.Items[i].Type != ref.kind {
					unsupported["部分数据扩展引用不存在或类型不匹配，未应用"] = true
				}
			}
		}
		if s.dnsFlags[item.UID] && len(s.dns) == 0 && len(s.dnsHosts) == 0 {
			unsupported["有订阅启用 DNS 覆写，但源配置缺少 DNS 内容"] = true
		}
		if item.Option.Rules != "" {
			if layer, err := s.ruleLayer(item.Option.Rules); err == nil && len(layer.Append) > 0 {
				unsupported["追加规则在 NetFlow 中位于 MATCH 前，顺序可能与 Verge 不同"] = true
			}
		}
	}
	for msg := range s.providerWarnings {
		unsupported[msg] = true
	}
	for _, msg := range []string{"脚本扩展会保留，但不会自动执行", "部分数据扩展引用不存在或类型不匹配，未应用", "追加规则在 NetFlow 中位于 MATCH 前，顺序可能与 Verge 不同", "有订阅启用 DNS 覆写，但源配置缺少 DNS 内容", "文件型规则或代理集合的外部文件未迁入，可能需要重新下载或修正路径", "HTTP 集合缓存未迁入，将在使用时重新下载"} {
		if unsupported[msg] {
			out.Warnings = append(out.Warnings, msg)
		}
	}
	out.Warnings = append(out.Warnings, "全局脚本及未关联扩展保存在原始存档中，不会自动执行", "订阅在激活时还会进行完整内核校验", "系统代理、TUN 和开机自启不会自动启用")
	return out
}
