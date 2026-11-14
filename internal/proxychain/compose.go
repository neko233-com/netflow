// Package proxychain composes an isolated dialer-proxy chain in memory.
// It never writes to a subscription or a provider cache.
package proxychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/utils"
	"go.yaml.in/yaml/v3"
)

// Hop names a resolved proxy and, for provider-backed nodes, its provider.
type Hop struct {
	Name     string `json:"name"`
	Provider string `json:"provider,omitempty"`
}

// Spec orders hops from entry to exit and chooses the selectable target group.
type Spec struct {
	Target string `json:"target"`
	Hops   []Hop  `json:"hops"`
}

// Result contains an ephemeral kernel configuration and its generated exit.
type Result struct {
	Config []byte
	Exit   string
}

func validName(s string) bool {
	return s != "" && len(s) <= 1024 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func (s Spec) Validate() error {
	if !validName(s.Target) || len(s.Hops) < 2 || len(s.Hops) > 8 {
		return errors.New("chain requires a target group and two to eight hops")
	}
	seen := make(map[Hop]bool, len(s.Hops))
	for _, hop := range s.Hops {
		if !validName(hop.Name) || (hop.Provider != "" && !validName(hop.Provider)) || seen[hop] {
			return errors.New("chain contains an invalid or duplicate hop")
		}
		seen[hop] = true
	}
	return nil
}

func mapping(value any, label string) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a mapping", label)
	}
	return m, nil
}

func sequence(value any, label string) ([]any, error) {
	if value == nil {
		return []any{}, nil
	}
	s, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sequence", label)
	}
	return s, nil
}

func enabled(value any) (bool, error) {
	switch v := value.(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b, nil
		}
	case int:
		if v == 0 || v == 1 {
			return v == 1, nil
		}
	}
	return false, errors.New("invalid include-all setting")
}

// copyMapping round-trips through YAML so nested provider options are not
// shared with the original in-memory mapping.
func copyMapping(in map[string]any) (map[string]any, error) {
	data, err := yaml.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func exactFilter(name string) string {
	// Mihomo separates alternative group filters with a literal backtick.
	return `\A` + strings.ReplaceAll(regexp.QuoteMeta(name), "`", `\x60`) + `\z`
}

// Compose adds private clones and hidden groups without changing the original
// proxy or provider definitions. Provider clones read the existing local cache
// as file providers, so they do not start independent network downloads.
func Compose(base []byte, spec Spec) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(base, &root); err != nil || root == nil {
		return Result{}, errors.New("configuration must be a YAML mapping")
	}
	proxies, err := sequence(root["proxies"], "proxies")
	if err != nil {
		return Result{}, err
	}
	groups, err := sequence(root["proxy-groups"], "proxy-groups")
	if err != nil {
		return Result{}, err
	}
	providers, err := mapping(root["proxy-providers"], "proxy-providers")
	if err != nil {
		return Result{}, err
	}
	inline := make(map[string]map[string]any, len(proxies))
	occupied := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "COMPATIBLE": true, "PASS": true, "PASS-RULE": true, "GLOBAL": true}
	seenGroups := map[string]bool{}
	var originalProxyNames, originalGroupNames, originalProviderNames []string
	for _, item := range proxies {
		p, err := mapping(item, "proxy")
		if err != nil {
			return Result{}, err
		}
		name, _ := p["name"].(string)
		if !validName(name) || occupied[name] {
			return Result{}, errors.New("invalid or duplicate proxy name")
		}
		inline[name], occupied[name] = p, true
		originalProxyNames = append(originalProxyNames, name)
	}
	var target map[string]any
	for _, item := range groups {
		g, err := mapping(item, "proxy group")
		if err != nil {
			return Result{}, err
		}
		name, _ := g["name"].(string)
		if !validName(name) || seenGroups[name] || (occupied[name] && name != "GLOBAL") {
			return Result{}, errors.New("invalid or duplicate proxy group name")
		}
		seenGroups[name] = true
		occupied[name] = true
		originalGroupNames = append(originalGroupNames, name)
		if name == spec.Target {
			target = g
		}
	}
	for name := range providers {
		if !validName(name) {
			return Result{}, errors.New("invalid provider name")
		}
		originalProviderNames = append(originalProviderNames, name)
	}
	sort.Strings(originalProxyNames)
	sort.Strings(originalProviderNames)
	// Freeze include-all expansion to the original definitions before adding
	// private clones, preventing those clones from appearing in other groups.
	for _, item := range groups {
		g := item.(map[string]any)
		all, e1 := enabled(g["include-all"])
		allProxies, e2 := enabled(g["include-all-proxies"])
		allProviders, e3 := enabled(g["include-all-providers"])
		if e1 != nil || e2 != nil || e3 != nil {
			return Result{}, errors.New("invalid group include-all setting")
		}
		if all || allProxies {
			current, err := sequence(g["proxies"], "group proxies")
			if err != nil {
				return Result{}, err
			}
			filter, ok := g["filter"].(string)
			if !ok && g["filter"] != nil {
				return Result{}, errors.New("group filter must be a string")
			}
			var filters []*regexp2.Regexp
			if filter != "" {
				for _, expression := range strings.Split(filter, "`") {
					compiled, err := regexp2.Compile(expression, regexp2.None)
					if err != nil {
						return Result{}, errors.New("invalid group filter")
					}
					compiled.MatchTimeout = 100 * time.Millisecond
					filters = append(filters, compiled)
				}
			}
			for _, name := range originalProxyNames {
				if len(filters) == 0 {
					current = append(current, name)
					continue
				}
				for _, expression := range filters {
					matched, err := expression.MatchString(name)
					if err != nil {
						return Result{}, errors.New("group filter failed")
					}
					if matched {
						current = append(current, name)
					}
				}
			}
			g["proxies"] = current
			delete(g, "include-all-proxies")
		}
		if all || allProviders {
			uses := make([]any, 0, len(originalProviderNames))
			for _, name := range originalProviderNames {
				uses = append(uses, name)
			}
			g["use"] = uses
			delete(g, "include-all-providers")
		}
		delete(g, "include-all")
		if all || allProxies {
			current, _ := sequence(g["proxies"], "group proxies")
			uses, err := sequence(g["use"], "group providers")
			if err != nil {
				return Result{}, err
			}
			if len(current) == 0 && len(uses) == 0 {
				fallback, _ := g["empty-fallback"].(string)
				if fallback == "" {
					fallback = "COMPATIBLE"
				}
				g["proxies"] = []any{fallback}
			}
		}
	}
	if target == nil && spec.Target == "GLOBAL" {
		// Recreate Mihomo's implicit GLOBAL members without private clones.
		members := []any{"DIRECT", "REJECT"}
		for _, item := range proxies {
			p := item.(map[string]any)
			kind, _ := p["type"].(string)
			if !strings.EqualFold(kind, "pass") && !strings.EqualFold(kind, "pass-rule") {
				members = append(members, p["name"])
			}
		}
		for _, name := range originalGroupNames {
			members = append(members, name)
		}
		target = map[string]any{"name": "GLOBAL", "type": "select", "proxies": members}
		groups = append(groups, target)
	}
	if target == nil || target["type"] != "select" {
		return Result{}, errors.New("target must be a selectable proxy group")
	}
	encoded, _ := json.Marshal(spec)
	sum := sha256.Sum256(encoded)
	prefix := "__netflow_chain_" + hex.EncodeToString(sum[:8])
	for i, hop := range spec.Hops {
		proxyName := fmt.Sprintf("%s_proxy_%d", prefix, i)
		providerName := fmt.Sprintf("%s_provider_%d", prefix, i)
		groupName := fmt.Sprintf("%s_hop_%d", prefix, i)
		_, providerExists := providers[providerName]
		if occupied[proxyName] || occupied[groupName] || providerExists {
			return Result{}, errors.New("generated chain name collides with the configuration")
		}
		previous := ""
		if i > 0 {
			previous = fmt.Sprintf("%s_hop_%d", prefix, i-1)
		}
		group := map[string]any{"name": groupName, "type": "select", "hidden": true, "empty-fallback": "REJECT"}
		if hop.Provider == "" {
			source := inline[hop.Name]
			if source == nil {
				return Result{}, errors.New("inline chain hop not found")
			}
			clone, err := copyMapping(source)
			if err != nil {
				return Result{}, err
			}
			clone["name"] = proxyName
			if previous != "" {
				clone["dialer-proxy"] = previous
			}
			proxies = append(proxies, clone)
			group["proxies"] = []any{proxyName}
		} else {
			source, err := mapping(providers[hop.Provider], "provider")
			if err != nil || providers[hop.Provider] == nil {
				return Result{}, errors.New("chain provider not found")
			}
			clone, err := copyMapping(source)
			if err != nil {
				return Result{}, err
			}
			kind, _ := clone["type"].(string)
			switch kind {
			case "http":
				path, ok := clone["path"].(string)
				if clone["path"] != nil && !ok {
					return Result{}, errors.New("invalid HTTP provider cache path")
				}
				if path == "" {
					url, ok := clone["url"].(string)
					if !ok || url == "" {
						return Result{}, errors.New("HTTP provider has no cache identity")
					}
					path = filepath.Join("proxies", utils.MakeHash([]byte(url)).String())
				}
				clone["type"], clone["path"] = "file", path
				for _, key := range []string{"url", "header", "proxy", "interval", "size-limit", "payload"} {
					delete(clone, key)
				}
			case "file":
				path, _ := clone["path"].(string)
				if path == "" {
					return Result{}, errors.New("file provider has no cache path")
				}
				delete(clone, "payload")
			case "inline":
			default:
				return Result{}, errors.New("unsupported chain provider type")
			}
			clone["health-check"] = map[string]any{"enable": false}
			if previous != "" {
				override, err := mapping(clone["override"], "provider override")
				if err != nil {
					return Result{}, err
				}
				override["dialer-proxy"] = previous
				expressions, err := sequence(override["override-expr"], "provider override expressions")
				if err != nil {
					return Result{}, err
				}
				// Existing expressions run after fixed override fields and may
				// set dialer-proxy; append our private chain assignment last.
				override["override-expr"] = append(expressions, `."dialer-proxy" = `+strconv.Quote(previous))
				clone["override"] = override
			}
			providers[providerName] = clone
			group["use"] = []any{providerName}
			group["filter"] = exactFilter(hop.Name)
		}
		groups = append(groups, group)
	}
	exit := fmt.Sprintf("%s_hop_%d", prefix, len(spec.Hops)-1)
	members, err := sequence(target["proxies"], "target proxies")
	if err != nil {
		return Result{}, err
	}
	target["proxies"] = append(members, exit)
	root["proxies"], root["proxy-groups"], root["proxy-providers"] = proxies, groups, providers
	body, err := yaml.Marshal(root)
	if err != nil {
		return Result{}, err
	}
	return Result{Config: body, Exit: exit}, nil
}
