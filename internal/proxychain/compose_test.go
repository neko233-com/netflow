package proxychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/utils"
	"go.yaml.in/yaml/v3"
)

func decodeConfig(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func byName(t *testing.T, raw any, name string) map[string]any {
	t.Helper()
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("not a sequence: %T", raw)
	}
	for _, item := range items {
		if m, ok := item.(map[string]any); ok && m["name"] == name {
			return m
		}
	}
	t.Fatalf("item %q not found", name)
	return nil
}

func TestComposePreservesSourceAndIncludeAllFilter(t *testing.T) {
	base := []byte(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: 10001}
  - {name: exit, type: socks5, server: 127.0.0.1, port: 10002, dialer-proxy: old}
  - {name: other, type: socks5, server: 127.0.0.1, port: 10003}
proxy-groups:
  - {name: Target, type: select, proxies: [entry, exit]}
  - {name: Filtered, type: select, include-all-proxies: true, filter: '^(entry|exit)$'}
rules: ['MATCH,Target']
`)
	original := string(base)
	result, err := Compose(base, Spec{Target: "Target", Hops: []Hop{{Name: "entry"}, {Name: "exit"}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(base) != original {
		t.Fatal("source bytes changed")
	}
	config := decodeConfig(t, result.Config)
	entry := byName(t, config["proxies"], "entry")
	exit := byName(t, config["proxies"], "exit")
	if entry["dialer-proxy"] != nil || exit["dialer-proxy"] != "old" {
		t.Fatal("original node definitions changed")
	}
	target := byName(t, config["proxy-groups"], "Target")
	if fmt.Sprint(target["proxies"]) != "[entry exit "+result.Exit+"]" {
		t.Fatalf("target membership: %v", target["proxies"])
	}
	filtered := byName(t, config["proxy-groups"], "Filtered")
	if fmt.Sprint(filtered["proxies"]) != "[entry exit]" || filtered["include-all-proxies"] != nil {
		t.Fatalf("include-all filter changed: %v", filtered)
	}
	hop := byName(t, config["proxy-groups"], result.Exit)
	if hop["hidden"] != true || hop["empty-fallback"] != "REJECT" {
		t.Fatalf("chain exit is not fail-closed: %v", hop)
	}
	cloneName := hop["proxies"].([]any)[0].(string)
	clone := byName(t, config["proxies"], cloneName)
	if clone["dialer-proxy"] == "old" || !strings.Contains(fmt.Sprint(clone["dialer-proxy"]), "_hop_0") {
		t.Fatalf("exit clone does not use entry hop: %v", clone)
	}
}

func TestProviderCloneUsesCacheAndCannotOverrideDialer(t *testing.T) {
	url := "https://example.invalid/sub?token=synthetic-secret"
	base := []byte(`proxy-providers:
  remote:
    type: http
    url: '` + url + `'
    payload: [{name: fallback, type: socks5, server: 127.0.0.1, port: 9}]
    override:
      additional-prefix: 'p-'
      override-expr: ['.dialer-proxy = "other"']
  local:
    type: file
    path: nodes.yaml
    payload: [{name: fallback, type: socks5, server: 127.0.0.1, port: 9}]
    override:
      override-expr: ['.dialer-proxy = "other"']
proxy-groups:
  - {name: Target, type: select, use: [remote, local]}
  - {name: Everyone, type: select, include-all-providers: true}
rules: ['MATCH,Target']
`)
	spec := Spec{Target: "Target", Hops: []Hop{{Name: "p-entry`x", Provider: "remote"}, {Name: "exit", Provider: "local"}}}
	result, err := Compose(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeConfig(t, result.Config)
	providers := config["proxy-providers"].(map[string]any)
	original := providers["remote"].(map[string]any)
	if original["url"] != url || original["type"] != "http" {
		t.Fatal("original HTTP provider changed")
	}
	if got := fmt.Sprint(byName(t, config["proxy-groups"], "Everyone")["use"]); got != "[local remote]" {
		t.Fatalf("private providers leaked into include-all: %s", got)
	}
	var clones []map[string]any
	for name, item := range providers {
		if strings.HasPrefix(name, "__netflow_chain_") {
			clones = append(clones, item.(map[string]any))
		}
	}
	if len(clones) != 2 {
		t.Fatalf("expected two provider clones, got %d", len(clones))
	}
	var remoteClone, localClone map[string]any
	for _, clone := range clones {
		if clone["path"] == filepath.Join("proxies", utils.MakeHash([]byte(url)).String()) {
			remoteClone = clone
		} else if clone["path"] == "nodes.yaml" {
			localClone = clone
		}
	}
	if remoteClone == nil || localClone == nil || remoteClone["type"] != "file" || remoteClone["url"] != nil || remoteClone["payload"] != nil || localClone["payload"] != nil {
		t.Fatal("provider clones did not use existing read-only cache sources")
	}
	override := localClone["override"].(map[string]any)
	expressions := override["override-expr"].([]any)
	if len(expressions) != 2 || !strings.Contains(expressions[1].(string), "_hop_0") {
		t.Fatalf("chain assignment missing: %v", expressions)
	}
	var ingress map[string]any
	for _, item := range config["proxy-groups"].([]any) {
		g := item.(map[string]any)
		if strings.HasSuffix(fmt.Sprint(g["name"]), "_hop_0") {
			ingress = g
		}
	}
	filter, err := regexp2.Compile(ingress["filter"].(string), regexp2.None)
	if err != nil {
		t.Fatal(err)
	}
	match, err := filter.MatchString("p-entry`x")
	other, otherErr := filter.MatchString("p-entry-x")
	if err != nil || otherErr != nil || !match || other {
		t.Fatal("provider name filter is not exact")
	}
}

func TestRejectsInvalidOrCollidingChains(t *testing.T) {
	base := []byte("proxies: [{name: a, type: socks5, server: 127.0.0.1, port: 1}, {name: b, type: socks5, server: 127.0.0.1, port: 2}]\nproxy-groups: [{name: Target, type: select, proxies: [a, b]}]\nrules: ['MATCH,Target']\n")
	for _, spec := range []Spec{
		{Target: "Target", Hops: []Hop{{Name: "a"}}},
		{Target: "Target", Hops: []Hop{{Name: "a"}, {Name: "a"}}},
		{Target: "Missing", Hops: []Hop{{Name: "a"}, {Name: "b"}}},
		{Target: "Target", Hops: []Hop{{Name: "a"}, {Name: "missing", Provider: "none"}}},
	} {
		if _, err := Compose(base, spec); err == nil {
			t.Fatalf("invalid chain accepted: %+v", spec)
		}
	}
	spec := Spec{Target: "Target", Hops: []Hop{{Name: "a"}, {Name: "b"}}}
	encoded, _ := json.Marshal(spec)
	sum := sha256.Sum256(encoded)
	name := "__netflow_chain_" + hex.EncodeToString(sum[:8]) + "_hop_0"
	collision := []byte(strings.Replace(string(base), "proxy-groups: [", "proxy-groups: [{name: "+name+", type: select, proxies: [a]}, ", 1))
	if _, err := Compose(collision, spec); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("generated name collision accepted: %v", err)
	}
}
