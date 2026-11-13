// Package kernelopts stores explicit user overrides separately from subscriptions.
package kernelopts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Nil fields inherit the active subscription. A zero port disables that listener.
type Options struct {
	Mode         *string `json:"mode,omitempty"`
	AllowLAN     *bool   `json:"allow_lan,omitempty"`
	IPv6         *bool   `json:"ipv6,omitempty"`
	UnifiedDelay *bool   `json:"unified_delay,omitempty"`
	LogLevel     *string `json:"log_level,omitempty"`
	TUNStack     *string `json:"tun_stack,omitempty"`
	MixedPort    *int    `json:"mixed_port,omitempty"`
	SOCKSPort    *int    `json:"socks_port,omitempty"`
	HTTPPort     *int    `json:"http_port,omitempty"`
	RedirPort    *int    `json:"redir_port,omitempty"`
	TProxyPort   *int    `json:"tproxy_port,omitempty"`
}

func (o Options) Validate() error {
	if o.Mode != nil {
		switch *o.Mode {
		case "rule", "global", "direct":
		default:
			return errors.New("无效的代理模式")
		}
	}
	if o.LogLevel != nil {
		switch *o.LogLevel {
		case "debug", "info", "warning", "error", "silent":
		default:
			return errors.New("无效的日志等级")
		}
	}
	if o.TUNStack != nil {
		switch *o.TUNStack {
		case "system", "gvisor", "mixed", "mips":
		default:
			return errors.New("无效的 TUN 协议栈")
		}
	}
	used := map[int]bool{}
	for _, port := range []*int{o.MixedPort, o.SOCKSPort, o.HTTPPort, o.RedirPort, o.TProxyPort} {
		if port == nil {
			continue
		}
		if *port < 0 || *port > 65535 {
			return errors.New("端口必须在 0 到 65535 之间")
		}
		if *port != 0 && used[*port] {
			return errors.New("代理端口不能重复")
		}
		used[*port] = *port != 0
	}
	if o.MixedPort != nil && *o.MixedPort == 0 {
		return errors.New("混合代理端口不能关闭")
	}
	return nil
}

func clone(o Options) Options {
	data, _ := json.Marshal(o)
	var out Options
	_ = json.Unmarshal(data, &out)
	return out
}

type Store struct {
	mu    sync.RWMutex
	path  string
	value Options
}

func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("配置目录为空")
	}
	s := &Store{path: filepath.Join(dir, "kernel-options.json")}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, errors.New("内核选项文件过大")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s.value); err != nil {
		return nil, fmt.Errorf("读取内核选项: %w", err)
	}
	return s, s.value.Validate()
}
func (s *Store) Snapshot() Options { s.mu.RLock(); defer s.mu.RUnlock(); return clone(s.value) }

// Replace persists before publishing the new snapshot; on failure neither changes.
func (s *Store) Replace(next Options) error {
	if err := next.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".kernel-options-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	s.value = clone(next)
	return nil
}

// Compose modifies only explicitly overridden top-level keys in memory.
func Compose(base []byte, o Options) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if o.Mode == nil && o.AllowLAN == nil && o.IPv6 == nil && o.UnifiedDelay == nil && o.LogLevel == nil && o.TUNStack == nil && o.MixedPort == nil && o.SOCKSPort == nil && o.HTTPPort == nil && o.RedirPort == nil && o.TProxyPort == nil {
		return base, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("内核配置必须是 YAML 映射")
	}
	root := doc.Content[0]
	set := func(key string, value any) error {
		var n yaml.Node
		if err := n.Encode(value); err != nil {
			return err
		}
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				root.Content[i+1] = &n
				return nil
			}
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &n)
		return nil
	}
	for _, x := range []struct {
		key     string
		value   any
		present bool
	}{
		{"mode", o.Mode, o.Mode != nil},
		{"allow-lan", o.AllowLAN, o.AllowLAN != nil}, {"ipv6", o.IPv6, o.IPv6 != nil}, {"unified-delay", o.UnifiedDelay, o.UnifiedDelay != nil}, {"log-level", o.LogLevel, o.LogLevel != nil},
		{"mixed-port", o.MixedPort, o.MixedPort != nil}, {"socks-port", o.SOCKSPort, o.SOCKSPort != nil}, {"port", o.HTTPPort, o.HTTPPort != nil}, {"redir-port", o.RedirPort, o.RedirPort != nil}, {"tproxy-port", o.TProxyPort, o.TProxyPort != nil},
	} {
		if x.present {
			if err := set(x.key, x.value); err != nil {
				return nil, err
			}
		}
	}
	if o.TUNStack != nil {
		// Resolve aliases/merge keys into a detached effective TUN mapping, so
		// updating the stack never changes another field sharing an anchor.
		var effective map[string]any
		if err := yaml.Unmarshal(base, &effective); err != nil {
			return nil, err
		}
		block := map[string]any{}
		if value, ok := effective["tun"]; ok && value != nil {
			var valid bool
			block, valid = value.(map[string]any)
			if !valid {
				return nil, errors.New("TUN 配置必须是 YAML 映射")
			}
		}
		block["stack"] = *o.TUNStack
		if err := set("tun", block); err != nil {
			return nil, err
		}
	}
	return yaml.Marshal(&doc)
}
