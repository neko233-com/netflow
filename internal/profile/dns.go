package profile

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ComposeDNS replaces the dns section in an in-memory copy of a subscription.
// The override is a YAML mapping for the contents of dns, not a complete config.
func ComposeDNS(base []byte, override string) ([]byte, error) {
	if len(override) > 64<<10 {
		return nil, errors.New("DNS 覆写不能超过 64 KiB")
	}
	if strings.TrimSpace(override) == "" {
		return nil, errors.New("DNS 覆写不能为空")
	}
	var section yaml.Node
	if err := yaml.Unmarshal([]byte(override), &section); err != nil {
		return nil, fmt.Errorf("DNS YAML 无效: %w", err)
	}
	if len(section.Content) != 1 || section.Content[0].Kind != yaml.MappingNode || len(section.Content[0].Content) == 0 {
		return nil, errors.New("DNS 覆写必须是非空的 YAML 映射")
	}
	var config yaml.Node
	if err := yaml.Unmarshal(base, &config); err != nil {
		return nil, err
	}
	if len(config.Content) != 1 || config.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置必须是 YAML 映射")
	}
	root := config.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "dns" {
			root.Content[i+1] = section.Content[0]
			return yaml.Marshal(&config)
		}
	}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "dns"}, section.Content[0])
	return yaml.Marshal(&config)
}

// ComposeVergeDNS reproduces Verge's DNS-page migration semantics: nonempty
// fields overlay the subscription DNS mapping and nonempty hosts replace the
// top-level hosts mapping. An empty, null or false override leaves a field as
// supplied by the subscription, as in Verge's DNS settings.
func ComposeVergeDNS(base []byte, override, hosts string) ([]byte, error) {
	if len(override) > 64<<10 || len(hosts) > 64<<10 {
		return nil, errors.New("DNS 或 hosts 覆写不能超过 64 KiB")
	}
	var config yaml.Node
	if err := yaml.Unmarshal(base, &config); err != nil {
		return nil, err
	}
	if len(config.Content) != 1 || config.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置必须是 YAML 映射")
	}
	root := config.Content[0]
	if (strings.TrimSpace(override) != "" || strings.TrimSpace(hosts) != "") && containsYAMLAlias(root) {
		// Resolve aliases before replacing any anchored subtree. Other users of
		// that anchor must keep their original independent values.
		resolved, err := MaterializeYAMLNode(&config)
		if err != nil {
			return nil, err
		}
		data, err := yaml.Marshal(resolved)
		if err != nil {
			return nil, err
		}
		if err = yaml.Unmarshal(data, &config); err != nil {
			return nil, err
		}
		base, root = data, config.Content[0]
	}
	if strings.TrimSpace(override) != "" {
		section, err := parseMapping(override)
		if err != nil {
			return nil, fmt.Errorf("DNS 覆写无效: %w", err)
		}
		dns := mappingValue(root, "dns")
		if dns == nil {
			// A YAML merge key can supply DNS even when the root has no direct
			// dns entry. Resolve that inherited value before adding the overlay.
			var effective struct {
				DNS yaml.Node `yaml:"dns"`
			}
			if err := yaml.Unmarshal(base, &effective); err != nil {
				return nil, err
			}
			if effective.DNS.Kind != 0 {
				dns = &effective.DNS
			}
		}
		if dns != nil && dns.Kind == yaml.AliasNode {
			dns = dns.Alias
		}
		if dns == nil || dns.Kind != yaml.MappingNode {
			dns = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		} else {
			dns, err = flattenMapping(dns, 0)
			if err != nil {
				return nil, err
			}
		}
		seen := make(map[string]bool)
		for i := 0; i+1 < len(section.Content); i += 2 {
			key, value := section.Content[i], section.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return nil, errors.New("DNS 覆写键无效或重复")
			}
			seen[key.Value] = true
			if vergeValueSet(value, 0) {
				setMappingValue(dns, key.Value, value)
			}
		}
		ipv6 := mappingValue(dns, "ipv6")
		var enabled bool
		if ipv6 != nil {
			_ = ipv6.Decode(&enabled)
		}
		mode, range6 := mappingValue(dns, "enhanced-mode"), mappingValue(dns, "fake-ip-range6")
		if enabled && (mode == nil || mode.Value == "fake-ip") && (range6 == nil || strings.TrimSpace(range6.Value) == "") {
			setMappingValue(dns, "fake-ip-range6", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "2001:2::0/64"})
		}
		setMappingValue(root, "dns", dns)
	}
	if strings.TrimSpace(hosts) != "" {
		section, err := parseMapping(hosts)
		if err != nil {
			return nil, fmt.Errorf("hosts 覆写无效: %w", err)
		}
		if len(section.Content) > 0 {
			setMappingValue(root, "hosts", section)
		}
	}
	return yaml.Marshal(&config)
}

func containsYAMLAlias(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsYAMLAlias(child) {
			return true
		}
	}
	return false
}

func parseMapping(text string) (*yaml.Node, error) {
	// Validate and resolve YAML aliases before moving a section into another
	// document, retaining mapping order for DNS policy matching.
	var value map[string]any
	if err := yaml.Unmarshal([]byte(text), &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("必须是 YAML 映射")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("必须是 YAML 映射")
	}
	resolved, err := MaterializeYAMLNode(doc.Content[0])
	if err != nil {
		return nil, err
	}
	return flattenMapping(resolved, 0)
}

// flattenMapping applies YAML merge keys while preserving the order of the
// winning entries. Explicit entries take precedence over merged entries.
func flattenMapping(node *yaml.Node, depth int) (*yaml.Node, error) {
	return flattenMappingContext(context.Background(), node, depth)
}
func flattenMappingContext(ctx context.Context, node *yaml.Node, depth int) (*yaml.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if node == nil || node.Kind != yaml.MappingNode || depth > 512 {
		return nil, errors.New("YAML 合并映射无效")
	}
	out := *node
	out.Anchor = ""
	out.Content = nil
	explicit := make(map[string]bool)
	for i := 0; i+1 < len(node.Content); i += 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := node.Content[i]
		if key.Tag == "!!merge" {
			continue
		}
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || explicit[key.Value] {
			return nil, errors.New("YAML 映射键无效或重复")
		}
		explicit[key.Value] = true
	}
	merged := make(map[string]bool)
	appendMerge := func(m *yaml.Node) error {
		resolved, err := flattenMappingContext(ctx, m, depth+1)
		if err != nil {
			return err
		}
		for j := 0; j+1 < len(resolved.Content); j += 2 {
			key := resolved.Content[j]
			if !explicit[key.Value] && !merged[key.Value] {
				merged[key.Value] = true
				out.Content = append(out.Content, key, resolved.Content[j+1])
			}
		}
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag != "!!merge" {
			out.Content = append(out.Content, key, value)
			continue
		}
		switch value.Kind {
		case yaml.MappingNode:
			if err := appendMerge(value); err != nil {
				return nil, err
			}
		case yaml.SequenceNode:
			for _, mapping := range value.Content {
				if err := appendMerge(mapping); err != nil {
					return nil, err
				}
			}
		default:
			return nil, errors.New("YAML 合并目标无效")
		}
	}
	return &out, nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func setMappingValue(node *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1] = value
			return
		}
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func vergeValueSet(node *yaml.Node, depth int) bool {
	if node == nil || depth > 32 {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return vergeValueSet(node.Alias, depth+1)
	}
	switch node.Kind {
	case yaml.SequenceNode, yaml.MappingNode:
		return len(node.Content) > 0
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return false
		case "!!bool":
			var value bool
			return node.Decode(&value) == nil && value
		case "!!str":
			return strings.TrimSpace(node.Value) != ""
		default:
			return true
		}
	default:
		return false
	}
}
