package profile

import (
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
