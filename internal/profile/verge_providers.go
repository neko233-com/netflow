package profile

import (
	"encoding/hex"
	"errors"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

// VergeProvider is a file-backed provider in an effective Verge profile.
type VergeProvider struct {
	Type string
	Path string
}

// VergeProviders resolves YAML anchors and merges before inspecting providers.
func VergeProviders(body []byte) ([]VergeProvider, error) {
	_, refs, err := visitVergeProviders(body, nil)
	return refs, err
}

// RemapVergeProviders changes only paths that were captured during import.
func RemapVergeProviders(body []byte, paths map[string]string) ([]byte, error) {
	if len(paths) == 0 {
		return body, nil
	}
	for _, dest := range paths {
		parts := strings.Split(dest, "/")
		if len(parts) != 3 || parts[0] != "verge-providers" || len(parts[1]) != 33 || parts[1][0] != 'v' || len(parts[2]) != 64 || path.Clean(dest) != dest || strings.ContainsAny(dest, `\:`) {
			return nil, errors.New("迁入的集合路径无效")
		}
		if _, err := hex.DecodeString(parts[1][1:]); err != nil {
			return nil, errors.New("迁入的集合路径无效")
		}
		if _, err := hex.DecodeString(parts[2]); err != nil {
			return nil, errors.New("迁入的集合路径无效")
		}
	}
	result, _, err := visitVergeProviders(body, paths)
	return result, err
}

func visitVergeProviders(body []byte, paths map[string]string) ([]byte, []VergeProvider, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("配置必须是 YAML 映射")
	}
	resolved, err := MaterializeYAMLNode(&doc)
	if err != nil {
		return nil, nil, err
	}
	root, err := flattenMapping(resolved.Content[0], 0)
	if err != nil {
		return nil, nil, err
	}
	resolved.Content[0] = root
	var refs []VergeProvider
	changed := false
	for _, section := range []string{"rule-providers", "proxy-providers"} {
		providers := mappingValue(root, section)
		if providers == nil || providers.Kind != yaml.MappingNode {
			continue
		}
		providers, err = flattenMapping(providers, 0)
		if err != nil {
			return nil, nil, err
		}
		setMappingValue(root, section, providers)
		for i := 1; i < len(providers.Content); i += 2 {
			entry := providers.Content[i]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			entry, err = flattenMapping(entry, 0)
			if err != nil {
				return nil, nil, err
			}
			providers.Content[i] = entry
			typ, p := mappingValue(entry, "type"), mappingValue(entry, "path")
			if typ != nil && typ.Kind == yaml.ScalarNode && typ.Value == "file" && (p == nil || p.Kind != yaml.ScalarNode || p.Tag != "!!str" || p.Value == "") {
				refs = append(refs, VergeProvider{Type: "file"})
				continue
			}
			if typ == nil || p == nil || typ.Kind != yaml.ScalarNode || p.Kind != yaml.ScalarNode || p.Tag != "!!str" || p.Value == "" {
				continue
			}
			if typ.Value != "file" && typ.Value != "http" {
				continue
			}
			refs = append(refs, VergeProvider{Type: typ.Value, Path: p.Value})
			if dest, ok := paths[p.Value]; ok {
				p.Value, p.Style = dest, 0
				changed = true
			}
		}
	}
	if !changed {
		return body, refs, nil
	}
	result, err := yaml.Marshal(resolved)
	return result, refs, err
}
