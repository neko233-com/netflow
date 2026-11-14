package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"go.yaml.in/yaml/v3"
)

const maxVergeScriptJSON = 8 << 20

// VergeScriptJSON materializes YAML aliases and merges and emits ordered JSON
// for Verge-style JavaScript. Mapping order is retained for ordered settings
// such as DNS policies. It rejects ambiguous keys and unsupported YAML tags.
func VergeScriptJSON(data []byte) ([]byte, error) {
	return VergeScriptJSONContext(context.Background(), data)
}

// VergeScriptJSONContext cancels alias expansion, merge resolution and output generation.
func VergeScriptJSONContext(ctx context.Context, data []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxVergeScriptJSON {
		return nil, errors.New("配置超过脚本输入大小限制")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		return nil, errors.New("配置 YAML 无效")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("配置必须只包含一个 YAML 文档")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("配置必须是 YAML 映射")
	}
	materialized, err := MaterializeYAMLNodeContext(ctx, doc.Content[0])
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	var emit func(*yaml.Node, int) error
	emit = func(node *yaml.Node, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if node == nil || depth > 512 {
			return errors.New("配置嵌套过深")
		}
		if out.Len() > maxVergeScriptJSON {
			return errors.New("配置超过脚本输入大小限制")
		}
		switch node.Kind {
		case yaml.MappingNode:
			mapping, err := flattenMappingContext(ctx, node, depth)
			if err != nil {
				return err
			}
			out.WriteByte('{')
			for i := 0; i+1 < len(mapping.Content); i += 2 {
				if i > 0 {
					out.WriteByte(',')
				}
				key, err := json.Marshal(mapping.Content[i].Value)
				if err != nil {
					return err
				}
				out.Write(key)
				out.WriteByte(':')
				if err := emit(mapping.Content[i+1], depth+1); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		case yaml.SequenceNode:
			out.WriteByte('[')
			for i, item := range node.Content {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := emit(item, depth+1); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		case yaml.ScalarNode:
			var value any
			switch node.Tag {
			case "!!str", "!!timestamp":
				value = node.Value
			case "!!null":
				value = nil
			case "!!bool", "!!int", "!!float":
				if err := node.Decode(&value); err != nil {
					return errors.New("配置标量无效")
				}
			default:
				return errors.New("配置包含脚本不支持的 YAML 类型")
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return errors.New("配置包含无法转换为 JSON 的值")
			}
			out.Write(encoded)
		default:
			return errors.New("配置包含脚本不支持的 YAML 节点")
		}
		if out.Len() > maxVergeScriptJSON {
			return errors.New("配置超过脚本输入大小限制")
		}
		return nil
	}
	if err := emit(materialized, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
