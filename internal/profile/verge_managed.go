package profile

import (
	"context"
	"errors"

	"go.yaml.in/yaml/v3"
)

// These settings are owned by NetFlow's runtime, not a migrated script.
// Keep the whole TUN block so scripts cannot silently change routing behavior.
var vergeManagedFields = map[string]bool{
	"port": true, "socks-port": true, "mixed-port": true, "redir-port": true, "tproxy-port": true,
	"allow-lan": true, "bind-address": true, "authentication": true, "skip-auth-prefixes": true,
	"lan-allowed-ips": true, "lan-disallowed-ips": true, "mode": true, "tun": true,
	"external-controller": true, "external-controller-tls": true, "external-controller-unix": true,
	"external-controller-pipe": true, "external-controller-cors": true, "external-ui": true,
	"external-ui-name": true, "external-ui-url": true, "external-doh-server": true, "secret": true,
	"listeners": true, "tunnels": true, "interface-name": true, "routing-mark": true,
	"iptables": true, "ebpf": true,
}

// RestoreVergeManagedFields preserves the data-extension values for fields
// owned by NetFlow after a Verge script runs. The input order of all other
// fields is kept, including provider mappings whose order can matter.
func RestoreVergeManagedFields(ctx context.Context, scripted, managed []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	base, err := VergeScriptJSONContext(ctx, managed)
	if err != nil {
		return nil, err
	}
	output, err := VergeScriptJSONContext(ctx, scripted)
	if err != nil {
		return nil, err
	}
	var oldDoc, nextDoc yaml.Node
	if yaml.Unmarshal(base, &oldDoc) != nil || yaml.Unmarshal(output, &nextDoc) != nil || len(oldDoc.Content) != 1 || len(nextDoc.Content) != 1 || oldDoc.Content[0].Kind != yaml.MappingNode || nextDoc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("invalid configuration mapping")
	}
	oldRoot, nextRoot := oldDoc.Content[0], nextDoc.Content[0]
	old := make(map[string][2]*yaml.Node)
	for i := 0; i+1 < len(oldRoot.Content); i += 2 {
		key, value := oldRoot.Content[i], oldRoot.Content[i+1]
		if vergeManagedFields[key.Value] {
			old[key.Value] = [2]*yaml.Node{key, value}
		}
	}
	seen := make(map[string]bool)
	kept := make([]*yaml.Node, 0, len(nextRoot.Content))
	for i := 0; i+1 < len(nextRoot.Content); i += 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, value := nextRoot.Content[i], nextRoot.Content[i+1]
		if !vergeManagedFields[key.Value] {
			kept = append(kept, key, value)
			continue
		}
		seen[key.Value] = true
		if pair, ok := old[key.Value]; ok {
			kept = append(kept, pair[0], pair[1])
		}
	}
	for i := 0; i+1 < len(oldRoot.Content); i += 2 {
		key := oldRoot.Content[i]
		if vergeManagedFields[key.Value] && !seen[key.Value] {
			pair := old[key.Value]
			kept = append(kept, pair[0], pair[1])
		}
	}
	nextRoot.Content = kept
	return yaml.Marshal(&nextDoc)
}
