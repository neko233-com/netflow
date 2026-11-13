// Package rewrite composes agent-managed rules without modifying subscription files.
package rewrite

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Layer is applied around the subscription's own rules. Remove contains exact
// subscription rules, while Append is inserted before its first MATCH rule.
type Layer struct {
	Prepend []string `json:"prepend,omitempty"`
	Append  []string `json:"append,omitempty"`
	Remove  []string `json:"remove,omitempty"`
}

// Connection is a time-limited matcher derived from one observed connection.
// It affects new connections matching its rule, not an already-open socket.
type Connection struct {
	ID        string    `json:"id"`
	ProfileID string    `json:"profile_id,omitempty"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expires_at"`
}

type State struct {
	Revision    uint64           `json:"revision"`
	Global      Layer            `json:"global"`
	Profiles    map[string]Layer `json:"profiles,omitempty"`
	Connections []Connection     `json:"connections,omitempty"`
}

func HasActive(s State, profileID string, now time.Time) bool {
	nonempty := func(l Layer) bool { return len(l.Prepend)+len(l.Append)+len(l.Remove) > 0 }
	if nonempty(s.Global) || nonempty(s.Profiles[profileID]) {
		return true
	}
	for _, c := range s.Connections {
		if c.ProfileID == profileID && c.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func (l Layer) Validate() error {
	for _, list := range [][]string{l.Prepend, l.Append, l.Remove} {
		if len(list) > 500 {
			return errors.New("a rule list may contain at most 500 entries")
		}
		for _, rule := range list {
			if strings.TrimSpace(rule) == "" || len(rule) > 4096 || strings.ContainsAny(rule, "\r\n\x00") {
				return errors.New("rules must be nonempty single lines of at most 4096 bytes")
			}
		}
	}
	return nil
}

func (s State) Validate() error {
	if err := s.Global.Validate(); err != nil {
		return err
	}
	if len(s.Profiles) > 1000 || len(s.Connections) > 1000 {
		return errors.New("too many rewrite layers")
	}
	for id, layer := range s.Profiles {
		if id == "" || len(id) > 128 {
			return errors.New("invalid profile id")
		}
		if err := layer.Validate(); err != nil {
			return fmt.Errorf("profile %s: %w", id, err)
		}
	}
	seen := make(map[string]bool)
	for _, c := range s.Connections {
		if c.ID == "" || len(c.ID) > 128 || seen[c.ID] || c.ExpiresAt.IsZero() {
			return errors.New("invalid connection override")
		}
		seen[c.ID] = true
		if err := (Layer{Prepend: []string{c.Rule}}).Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Compose produces an in-memory config. Precedence is connection, profile,
// global, then the remaining base rules; original files are never changed.
func Compose(base []byte, state State, profileID string, now time.Time) ([]byte, []string, error) {
	if err := state.Validate(); err != nil {
		return nil, nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("configuration must be a YAML mapping")
	}
	root := doc.Content[0]
	var seq *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			if seq != nil {
				return nil, nil, errors.New("duplicate rules key")
			}
			seq = root.Content[i+1]
		}
	}
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}, seq)
	}
	if seq.Kind == yaml.ScalarNode && seq.Tag == "!!null" {
		seq.Kind, seq.Tag, seq.Value = yaml.SequenceNode, "!!seq", ""
	}
	if seq.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("rules must be a YAML sequence")
	}
	profile := state.Profiles[profileID]
	drop := make(map[string]bool)
	for _, r := range append(append([]string(nil), state.Global.Remove...), profile.Remove...) {
		drop[strings.TrimSpace(r)] = true
	}
	var rules []string
	for i := len(state.Connections) - 1; i >= 0; i-- {
		c := state.Connections[i]
		if c.ProfileID == profileID && c.ExpiresAt.After(now) {
			rules = append(rules, c.Rule)
		}
	}
	rules = append(rules, profile.Prepend...)
	rules = append(rules, state.Global.Prepend...)
	var baseRules []string
	for _, node := range seq.Content {
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
			return nil, nil, errors.New("each rule must be a string")
		}
		if !drop[strings.TrimSpace(node.Value)] {
			baseRules = append(baseRules, node.Value)
		}
	}
	appendAt := len(baseRules)
	for i, r := range baseRules {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r)), "MATCH,") {
			appendAt = i
			break
		}
	}
	rules = append(rules, baseRules[:appendAt]...)
	rules = append(rules, profile.Append...)
	rules = append(rules, state.Global.Append...)
	rules = append(rules, baseRules[appendAt:]...)
	seq.Content = nil
	for _, r := range rules {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: r})
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	return out.Bytes(), rules, nil
}
