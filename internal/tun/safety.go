package tun

import (
	"errors"

	"go.yaml.in/yaml/v3"
)

// EnsureDisabled prevents a subscription from opening a TUN device when the
// application has no permission to manage it. It leaves the input untouched
// when the effective YAML already has TUN disabled, including merged keys.
func EnsureDisabled(data []byte) ([]byte, error) {
	var effective struct {
		Tun struct {
			Enable bool `yaml:"enable"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal(data, &effective); err != nil {
		return nil, err
	}
	if !effective.Tun.Enable {
		return data, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置必须是 YAML 映射")
	}
	root := doc.Content[0]
	var block *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "tun" {
			block = root.Content[i+1]
			break
		}
	}
	if block == nil {
		block = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tun"}, block)
	}
	if block.Kind == yaml.AliasNode {
		// Do not mutate a shared anchor used elsewhere.
		copyBlock := *block.Alias
		copyBlock.Anchor = ""
		copyBlock.Content = append([]*yaml.Node(nil), block.Alias.Content...)
		*block = copyBlock
	}
	if block.Kind != yaml.MappingNode {
		return nil, errors.New("TUN 配置必须是 YAML 映射")
	}
	value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}
	for i := 0; i+1 < len(block.Content); i += 2 {
		if block.Content[i].Value == "enable" {
			block.Content[i+1] = value
			return yaml.Marshal(&doc)
		}
	}
	block.Content = append(block.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enable"}, value)
	return yaml.Marshal(&doc)
}
