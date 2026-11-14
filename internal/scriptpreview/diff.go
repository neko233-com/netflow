package scriptpreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/neko233-com/netflow/internal/profile"
)

// TopLevelChanges exposes only known field names and a count for other keys.
// Values and unknown names are intentionally omitted because either can carry
// subscription credentials. It is a summary, not a complete rule preview.
type TopLevelChanges struct {
	Fields     []string `json:"fields"`
	OtherCount int      `json:"other_count"`
}

var knownFields = map[string]bool{
	"port": true, "socks-port": true, "mixed-port": true, "redir-port": true, "tproxy-port": true,
	"allow-lan": true, "bind-address": true, "mode": true, "log-level": true, "ipv6": true,
	"authentication": true, "skip-auth-prefixes": true, "lan-allowed-ips": true, "lan-disallowed-ips": true,
	"unified-delay": true, "tcp-concurrent": true, "find-process-mode": true, "interface-name": true, "routing-mark": true,
	"external-controller": true, "external-controller-tls": true, "external-controller-unix": true, "external-controller-pipe": true,
	"external-controller-cors": true, "external-ui": true, "external-ui-name": true, "external-ui-url": true, "external-doh-server": true, "secret": true,
	"geodata-mode": true, "geodata-loader": true, "geo-auto-update": true, "geo-update-interval": true, "geox-url": true,
	"global-ua": true, "etag-support": true, "profile": true, "dns": true, "hosts": true, "tun": true, "sniffer": true, "ntp": true, "experimental": true,
	"proxies": true, "proxy-groups": true, "proxy-providers": true, "rule-providers": true, "rules": true, "sub-rules": true, "listeners": true, "tunnels": true,
}

// Summarize compares ordered normalized YAML/JSON without returning values.
// The caller is responsible for separately previewing full rules and other
// routing-relevant changes before authorizing an application.
func Summarize(ctx context.Context, before, after []byte) (TopLevelChanges, error) {
	var result TopLevelChanges
	if ctx == nil {
		return result, errors.New("context is required")
	}
	left, err := profile.VergeScriptJSONContext(ctx, before)
	if err != nil {
		return result, err
	}
	right, err := profile.VergeScriptJSONContext(ctx, after)
	if err != nil {
		return result, err
	}
	var a, b map[string]json.RawMessage
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return result, errors.New("invalid configuration")
	}
	seen := make(map[string]bool, len(a)+len(b))
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	result.Fields = []string{}
	for key := range seen {
		if err := ctx.Err(); err != nil {
			return TopLevelChanges{}, err
		}
		av, aok := a[key]
		bv, bok := b[key]
		if aok == bok && bytes.Equal(av, bv) {
			continue
		}
		if knownFields[key] {
			result.Fields = append(result.Fields, key)
		} else {
			result.OtherCount++
		}
	}
	sort.Strings(result.Fields)
	return result, nil
}
