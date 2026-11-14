package profile

import (
	"context"
	"errors"

	"go.yaml.in/yaml/v3"
)

// MaterializeYAMLNode expands aliases without reordering mapping entries.
// The limits also reject recursive or excessive alias expansion.
func MaterializeYAMLNode(node *yaml.Node) (*yaml.Node, error) {
	return MaterializeYAMLNodeContext(context.Background(), node)
}

// MaterializeYAMLNodeContext also stops alias expansion when the caller cancels.
func MaterializeYAMLNodeContext(ctx context.Context, node *yaml.Node) (*yaml.Node, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	remaining := 1000000
	active := make(map[*yaml.Node]bool)
	var clone func(*yaml.Node, int) (*yaml.Node, error)
	clone = func(n *yaml.Node, depth int) (*yaml.Node, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n == nil || depth > 512 || remaining == 0 {
			return nil, errors.New("YAML 引用过深或过大")
		}
		if active[n] {
			return nil, errors.New("YAML 包含循环引用")
		}
		remaining--
		active[n] = true
		defer delete(active, n)
		if n.Kind == yaml.AliasNode {
			return clone(n.Alias, depth+1)
		}
		copyNode := *n
		copyNode.Anchor, copyNode.Alias = "", nil
		copyNode.Content = make([]*yaml.Node, 0, len(n.Content))
		for _, child := range n.Content {
			copied, err := clone(child, depth+1)
			if err != nil {
				return nil, err
			}
			copyNode.Content = append(copyNode.Content, copied)
		}
		return &copyNode, nil
	}
	return clone(node, 0)
}
