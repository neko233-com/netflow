package migration

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/safepath"
	"go.yaml.in/yaml/v3"
)

type ExportResult struct {
	Exported int      `json:"exported"`
	Warnings []string `json:"warnings,omitempty"`
}

func managedFile(root, subdir, relative string) (string, error) {
	info, err := os.Lstat(filepath.Join(root, subdir))
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("数据目录不能是链接或重解析点")
	}
	base, err := safepath.Canonical(filepath.Join(root, subdir))
	if err != nil {
		return "", err
	}
	file, err := safepath.Canonical(filepath.Join(root, relative))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, file)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("数据文件路径无效")
	}
	info, err = os.Stat(file)
	if err != nil {
		return "", err
	}
	limit := int64(maxEntry)
	if subdir == "verge-imports" {
		limit = maxTotal
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("数据文件无效或过大")
	}
	return file, nil
}

// readManaged confines the actual read, not just the preliminary path check.
func readManaged(root, subdir, relative string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(root) || !filepath.IsLocal(relative) {
		return nil, errors.New("数据文件路径无效")
	}
	rel, err := filepath.Rel(subdir, relative)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return nil, errors.New("数据文件路径无效")
	}
	parent, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	info, err := parent.Lstat(subdir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("数据目录不能是链接或重解析点")
	}
	dir, err := parent.OpenRoot(subdir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, err := dir.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("数据文件无效或过大")
	}
	return readBounded(f, limit)
}

// ExportVerge writes a new Clash Verge-compatible ZIP and never overwrites an
// existing file. It carries subscription data and recoverable extension files.
// Callers must hold the NetFlow directory lock while reading its state.
func ExportVerge(target, destination string) (ExportResult, error) {
	if !filepath.IsAbs(target) || !filepath.IsAbs(destination) {
		return ExportResult{}, errors.New("配置目录和导出路径必须是绝对路径")
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil {
		return ExportResult{}, err
	}
	if len(catalog.Items) == 0 {
		return ExportResult{}, errors.New("没有可迁出的订阅")
	}
	rs, err := rewrite.Open(target)
	if err != nil {
		return ExportResult{}, err
	}
	state := rs.Snapshot()
	opts, err := kernelopts.Open(target)
	if err != nil {
		return ExportResult{}, err
	}
	result := ExportResult{Warnings: []string{"备份包含订阅凭据，请妥善保管", "规则追加顺序可能与 NetFlow 不同，请在 Verge 中检查", "系统代理、TUN 和开机自启不会自动启用"}}
	if len(state.Connections) > 0 {
		result.Warnings = append(result.Warnings, "临时连接级规则不会迁出")
	}
	output := map[string][]byte{}
	type providerEntry struct {
		name string
		data []byte
	}
	providerOutput := map[string]providerEntry{}
	providerConflicts := map[string]bool{}
	index := vergeIndex{Items: []vergeItem{}}
	seenArchive := map[string][]byte{}
	hasScript := false
	hasUnlinked := false
	for _, p := range catalog.Items {
		if p.Type != "remote" && p.Type != "local" {
			continue
		}
		body, err := readManaged(target, "profiles", p.File, maxEntry)
		if err != nil {
			return ExportResult{}, err
		}
		if err = validProfile(body); err != nil {
			return ExportResult{}, err
		}
		if _, err = profile.RemapVergeProviders(body, p.Option.VergeProviderPaths); err != nil {
			return ExportResult{}, err
		}
		for original, managed := range p.Option.VergeProviderPaths {
			rel := providerRelative(original, "")
			if rel == "" {
				result.Warnings = append(result.Warnings, "部分集合的原始路径不适合写入备份，请在 Verge 中检查")
				continue
			}
			data, e := readManaged(target, "verge-providers", filepath.FromSlash(managed), maxEntry)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return ExportResult{}, e
			}
			key := strings.ToLower(rel)
			if previous, ok := providerOutput[key]; ok && !bytes.Equal(previous.data, data) {
				providerConflicts[key] = true
				delete(providerOutput, key)
			}
			if !providerConflicts[key] {
				providerOutput[key] = providerEntry{name: rel, data: data}
			}
		}
		id, err := randomID()
		if err != nil {
			return ExportResult{}, err
		}
		entry := vergeItem{UID: id, Type: p.Type, Name: p.Name, Desc: p.Description, URL: p.URL, Home: p.Home, File: id + ".yaml", Option: vergeOption{UpdateInterval: p.Option.UpdateInterval, AllowAutoUpdate: p.Option.AllowAutoUpdate, WithProxy: p.Option.UseSystemProxy, SelfProxy: p.Option.UseClashProxy, UserAgent: p.Option.UserAgent, Timeout: p.Option.TimeoutSeconds}}
		if !p.Updated.IsZero() {
			entry.Updated = p.Updated.Unix()
		}
		if p.Used > 0 {
			entry.Extra.Download = uint64(p.Used)
		}
		if p.Total > 0 {
			entry.Extra.Total = uint64(p.Total)
		}
		if !p.Expire.IsZero() && p.Expire.Unix() > 0 {
			entry.Extra.Expire = uint64(p.Expire.Unix())
		}
		for _, sel := range p.Selected {
			entry.Selected = append(entry.Selected, vergeSelection{Name: sel.Name, Now: sel.Now})
		}
		if p.UID == catalog.Current {
			index.Current = id
		}
		var origin *Source
		var original vergeItem
		if p.Option.VergeArchive != "" && p.Option.VergeUID != "" {
			archive := seenArchive[p.Option.VergeArchive]
			if archive == nil {
				archive, err = readManaged(target, "verge-imports", p.Option.VergeArchive, maxTotal)
				if err != nil {
					return ExportResult{}, err
				}
				seenArchive[p.Option.VergeArchive] = archive
			}
			origin, err = readArchiveExtensionsWithScript(archive, p.Option.VergeUID, true)
			if err != nil {
				return ExportResult{}, err
			}
			for _, item := range origin.index.Items {
				if item.UID == p.Option.VergeUID {
					original = item
					break
				}
			}
			if original.UID == "" {
				return ExportResult{}, errors.New("原始 Verge 扩展记录不存在")
			}
			hasUnlinked = true
		}
		copyExtension := func(kind, oldID string) (string, error) {
			if oldID == "" {
				return "", nil
			}
			if origin == nil {
				return "", errors.New("缺少原始扩展数据")
			}
			var source vergeItem
			for _, it := range origin.index.Items {
				if it.UID == oldID && it.Type == kind {
					source = it
					break
				}
			}
			if source.UID == "" {
				return "", errors.New("原始扩展引用无效")
			}
			newID, err := randomID()
			if err != nil {
				return "", err
			}
			suffix := filepath.Ext(source.File)
			name := newID + suffix
			output["profiles/"+name] = origin.files["profiles/"+source.File]
			index.Items = append(index.Items, vergeItem{UID: newID, Type: kind, Name: source.Name, File: name})
			if kind == "script" {
				hasScript = true
			}
			return newID, nil
		}
		if entry.Option.Proxies, err = copyExtension("proxies", original.Option.Proxies); err != nil {
			return ExportResult{}, err
		}
		if entry.Option.Groups, err = copyExtension("groups", original.Option.Groups); err != nil {
			return ExportResult{}, err
		}
		if entry.Option.Script, err = copyExtension("script", original.Option.Script); err != nil {
			return ExportResult{}, err
		}
		var mergeBody []byte
		if original.Option.Merge != "" {
			for _, it := range origin.index.Items {
				if it.UID == original.Option.Merge && it.Type == "merge" {
					mergeBody = origin.files["profiles/"+it.File]
					break
				}
			}
			if mergeBody == nil {
				return ExportResult{}, errors.New("原始合并扩展不存在")
			}
		}
		if p.Option.DNSEnabled {
			var mergeDoc yaml.Node
			if len(mergeBody) > 0 {
				if err := yaml.Unmarshal(mergeBody, &mergeDoc); err != nil {
					return ExportResult{}, errors.New("原始合并扩展无效")
				}
			}
			if len(mergeDoc.Content) == 0 {
				mergeBody = []byte("{}")
			}
			if p.Option.DNSVergeMerge {
				mergeBody, err = profile.ComposeVergeDNS(mergeBody, p.Option.DNSOverride, p.Option.DNSVergeHosts)
			} else {
				mergeBody, err = profile.ComposeDNS(mergeBody, p.Option.DNSOverride)
				if err == nil && p.Option.DNSVergeHosts != "" {
					mergeBody, err = profile.ComposeVergeDNS(mergeBody, "", p.Option.DNSVergeHosts)
				}
			}
			if err != nil {
				return ExportResult{}, err
			}
		}
		if mergeBody != nil {
			mid, err := randomID()
			if err != nil {
				return ExportResult{}, err
			}
			entry.Option.Merge = mid
			name := mid + ".yaml"
			output["profiles/"+name] = mergeBody
			index.Items = append(index.Items, vergeItem{UID: mid, Type: "merge", Name: "NetFlow merge", File: name})
		}
		layer := state.Profiles[p.UID]
		global := state.Global
		rules := struct {
			Prepend []string `yaml:"prepend"`
			Append  []string `yaml:"append"`
			Delete  []string `yaml:"delete"`
		}{append(append([]string{}, layer.Prepend...), global.Prepend...), append(append([]string{}, layer.Append...), global.Append...), append(append([]string{}, layer.Remove...), global.Remove...)}
		if len(rules.Prepend)+len(rules.Append)+len(rules.Delete) > 0 {
			rid, err := randomID()
			if err != nil {
				return ExportResult{}, err
			}
			entry.Option.Rules = rid
			name := rid + ".yaml"
			output["profiles/"+name], err = yaml.Marshal(rules)
			if err != nil {
				return ExportResult{}, err
			}
			index.Items = append(index.Items, vergeItem{UID: rid, Type: "rules", Name: "NetFlow rules", File: name})
		}
		output["profiles/"+entry.File] = body
		index.Items = append(index.Items, entry)
		result.Exported++
	}
	if result.Exported == 0 {
		return ExportResult{}, errors.New("没有可迁出的订阅")
	}
	if index.Current == "" {
		for _, it := range index.Items {
			if it.Type == "remote" || it.Type == "local" {
				index.Current = it.UID
				break
			}
		}
	}
	if hasScript {
		result.Warnings = append(result.Warnings, "备份包含保留的 Verge 脚本，目标程序可能执行它们")
	}
	if hasUnlinked {
		result.Warnings = append(result.Warnings, "未关联到订阅的全局扩展未写入备份")
	}
	output["profiles.yaml"], err = yaml.Marshal(index)
	if err != nil {
		return ExportResult{}, err
	}
	output["verge.yaml"], err = yaml.Marshal(map[string]any{"enable_system_proxy": false, "enable_tun_mode": false, "enable_auto_launch": false})
	if err != nil {
		return ExportResult{}, err
	}
	opt := opts.Snapshot()
	cfg := map[string]any{"tun": map[string]any{"enable": false}}
	for _, pair := range []struct {
		key   string
		value any
	}{{"mode", opt.Mode}, {"allow-lan", opt.AllowLAN}, {"ipv6", opt.IPv6}, {"unified-delay", opt.UnifiedDelay}, {"log-level", opt.LogLevel}, {"mixed-port", opt.MixedPort}, {"socks-port", opt.SOCKSPort}, {"port", opt.HTTPPort}, {"redir-port", opt.RedirPort}, {"tproxy-port", opt.TProxyPort}} {
		switch v := pair.value.(type) {
		case *string:
			if v != nil {
				cfg[pair.key] = *v
			}
		case *bool:
			if v != nil {
				cfg[pair.key] = *v
			}
		case *int:
			if v != nil {
				cfg[pair.key] = *v
			}
		}
	}
	output["config.yaml"], err = yaml.Marshal(cfg)
	if err != nil {
		return ExportResult{}, err
	}
	providerNames := make([]string, 0, len(providerOutput))
	for name := range providerOutput {
		providerNames = append(providerNames, name)
	}
	for _, name := range providerNames {
		for parent := filepath.ToSlash(filepath.Dir(name)); parent != "." && parent != "/"; parent = filepath.ToSlash(filepath.Dir(parent)) {
			if _, ok := providerOutput[parent]; ok {
				providerConflicts[parent], providerConflicts[name] = true, true
			}
		}
	}
	for key, entry := range providerOutput {
		if providerConflicts[key] {
			continue
		}
		conflict := false
		for existing := range output {
			a, b := strings.ToLower(existing), strings.ToLower(entry.name)
			if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
				conflict = true
				break
			}
		}
		if conflict {
			providerConflicts[key] = true
			continue
		}
		output[entry.name] = entry.data
	}
	if len(providerConflicts) > 0 {
		result.Warnings = append(result.Warnings, "集合文件路径冲突，冲突文件未写入备份")
	}
	total := 0
	for _, b := range output {
		total += len(b)
		if total > maxTotal {
			return ExportResult{}, errors.New("迁出数据过大")
		}
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ExportResult{}, err
	}
	zw := zip.NewWriter(f)
	for name, data := range output {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		w, e := zw.CreateHeader(header)
		if e != nil {
			err = e
			break
		}
		if _, e = w.Write(data); e != nil {
			err = e
			break
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
		_ = os.Remove(destination)
		return ExportResult{}, fmt.Errorf("导出失败: %w", err)
	}
	return result, nil
}
