package profile

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// VergeExtensions contains data-only profile enhancements. Scripts are never
// executed by this composition path.
type VergeExtensions struct {
	Proxies, Groups, GlobalMerge, ProfileMerge []byte
}

// ComposeVergeExtensions applies proxy and group sequences, followed by the
// global and subscription merges. The original subscription is not modified.
func ComposeVergeExtensions(base []byte, ext VergeExtensions) ([]byte, error) {
	if len(ext.Proxies)+len(ext.Groups)+len(ext.GlobalMerge)+len(ext.ProfileMerge) == 0 {
		return base, nil
	}
	for _, data := range [][]byte{ext.Proxies, ext.Groups, ext.GlobalMerge, ext.ProfileMerge} {
		if len(data) > 8<<20 {
			return nil, errors.New("Verge 扩展文件超过大小限制")
		}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置必须是 YAML 映射")
	}
	resolved, err := MaterializeYAMLNode(&doc)
	if err != nil {
		return nil, err
	}
	root, err := flattenMapping(resolved.Content[0], 0)
	if err != nil {
		return nil, err
	}
	resolved.Content[0] = root
	for _, step := range []struct {
		field string
		data  []byte
	}{{"proxies", ext.Proxies}, {"proxy-groups", ext.Groups}} {
		if len(step.data) > 0 {
			if err := applyVergeSequence(root, step.field, step.data); err != nil {
				return nil, fmt.Errorf("Verge %s 扩展无效: %w", step.field, err)
			}
		}
	}
	for _, data := range [][]byte{ext.GlobalMerge, ext.ProfileMerge} {
		if len(data) == 0 {
			continue
		}
		overlay, err := parseVergeMapping(data)
		if err != nil {
			return nil, fmt.Errorf("Verge 合并扩展无效: %w", err)
		}
		if overlay == nil {
			continue
		}
		if err := mergeVergeMapping(root, overlay, true); err != nil {
			return nil, err
		}
	}
	return yaml.Marshal(resolved)
}

// Verge's empty or comment-only extension files are equivalent to an empty
// mapping, rather than a malformed profile.
func parseVergeMapping(data []byte) (*yaml.Node, error) {
	var probe yaml.Node
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if len(probe.Content) == 0 || (probe.Content[0].Kind == yaml.ScalarNode && probe.Content[0].Tag == "!!null") {
		return nil, nil
	}
	return parseMapping(string(data))
}

func vergeSequence(node *yaml.Node, field string) ([]*yaml.Node, error) {
	value := mappingValue(node, field)
	if value == nil {
		return nil, nil
	}
	if value.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s 必须是列表", field)
	}
	return value.Content, nil
}

func vergeItemName(item *yaml.Node) string {
	if item.Kind == yaml.ScalarNode && item.Tag == "!!str" {
		return item.Value
	}
	if value := mappingValue(item, "name"); value != nil && value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
		return value.Value
	}
	return ""
}

func vergeItemDeleted(item *yaml.Node, deleted map[string]bool) bool {
	if item.Kind == yaml.ScalarNode && item.Tag == "!!str" {
		return deleted[item.Value]
	}
	if value := mappingValue(item, "name"); value != nil && value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
		return deleted[value.Value]
	}
	return false
}

func applyVergeSequence(root *yaml.Node, field string, data []byte) error {
	seq, err := parseVergeMapping(data)
	if err != nil {
		return err
	}
	if seq == nil {
		return nil
	}
	prepend, err := vergeSequence(seq, "prepend")
	if err != nil {
		return err
	}
	appendItems, err := vergeSequence(seq, "append")
	if err != nil {
		return err
	}
	remove, err := vergeSequence(seq, "delete")
	if err != nil {
		return err
	}
	deleted := make(map[string]bool, len(remove))
	for _, item := range remove {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return errors.New("delete 必须包含字符串")
		}
		deleted[item.Value] = true
	}
	result := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	result.Content = append(result.Content, prepend...)
	if old := mappingValue(root, field); old != nil && old.Kind == yaml.SequenceNode {
		for _, item := range old.Content {
			if !vergeItemDeleted(item, deleted) {
				result.Content = append(result.Content, item)
			}
		}
	}
	result.Content = append(result.Content, appendItems...)
	setMappingValue(root, field, result)
	if field != "proxies" {
		return nil
	}
	groups := mappingValue(root, "proxy-groups")
	if groups == nil || groups.Kind != yaml.SequenceNode {
		return nil
	}
	added, seen := []string{}, map[string]bool{}
	for _, item := range append(append([]*yaml.Node(nil), prepend...), appendItems...) {
		if name := vergeItemName(item); name != "" && !seen[name] {
			seen[name] = true
			added = append(added, name)
		}
	}
	updated := *groups
	updated.Content = nil
	addedToSelector := false
	for _, group := range groups.Content {
		if group.Kind != yaml.MappingNode {
			updated.Content = append(updated.Content, group)
			continue
		}
		copyGroup, err := flattenMapping(group, 0)
		if err != nil {
			return err
		}
		old := mappingValue(copyGroup, "proxies")
		var items []*yaml.Node
		if old != nil && old.Kind == yaml.SequenceNode {
			for _, item := range old.Content {
				if !vergeItemDeleted(item, deleted) {
					items = append(items, item)
				}
			}
		}
		typ := mappingValue(copyGroup, "type")
		selector := typ != nil && (strings.EqualFold(typ.Value, "select") || strings.EqualFold(typ.Value, "selector"))
		if !addedToSelector && len(added) > 0 && selector {
			unique, merged := map[string]bool{}, []*yaml.Node{}
			for _, name := range added {
				unique[name] = true
				merged = append(merged, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name})
			}
			for _, item := range items {
				name := vergeItemName(item)
				if item.Kind == yaml.ScalarNode && item.Tag == "!!str" && unique[name] {
					continue
				}
				if name != "" {
					unique[name] = true
				}
				merged = append(merged, item)
			}
			items, addedToSelector = merged, true
		}
		if old != nil && old.Kind == yaml.SequenceNode || addedToSelector && selector && len(items) > 0 {
			setMappingValue(copyGroup, "proxies", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
		}
		updated.Content = append(updated.Content, copyGroup)
	}
	setMappingValue(root, "proxy-groups", &updated)
	return nil
}

func mergeVergeMapping(target, overlay *yaml.Node, top bool) error {
	for i := 0; i+1 < len(overlay.Content); i += 2 {
		key, value := overlay.Content[i].Value, overlay.Content[i+1]
		if top {
			key = strings.ToLower(key)
		}
		old := mappingValue(target, key)
		if !(top && key == "hosts") && old != nil && old.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
			merged, err := flattenMapping(old, 0)
			if err != nil {
				return err
			}
			value, err = flattenMapping(value, 0)
			if err != nil {
				return err
			}
			if top && key == "dns" {
				for j := 0; j+1 < len(value.Content); j += 2 {
					setMappingValue(merged, value.Content[j].Value, value.Content[j+1])
				}
			} else if err := mergeVergeMapping(merged, value, false); err != nil {
				return err
			}
			setMappingValue(target, key, merged)
		} else {
			setMappingValue(target, key, value)
		}
	}
	return nil
}
