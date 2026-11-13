package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type agentProposal struct {
	change        agent.Change
	state         rewrite.State
	revision      uint64
	activeProfile string
	sources       map[string][32]byte
	expires       time.Time
}

func (a *App) agentStatus() (agent.Status, error) {
	if a.rewrites == nil || a.core == nil || a.profiles == nil {
		return agent.Status{}, errors.New("agent service is not ready")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return agent.Status{}, err
	}
	st := a.core.Status()
	connections, _, _ := a.core.Connections()
	out := agent.Status{Running: st.Running, Mode: st.Mode, ActiveProfile: a.core.ProfileID(), Revision: a.rewrites.Snapshot().Revision, Connections: connections, Overrides: a.rewrites.Snapshot()}
	for _, p := range catalog.Items {
		out.Profiles = append(out.Profiles, agent.Profile{ID: p.UID, Name: p.Name, Active: p.UID == out.ActiveProfile})
	}
	return out, nil
}

func (a *App) agentPreview(change agent.Change) (agent.Preview, error) {
	if a.rewrites == nil || a.core == nil || a.profiles == nil {
		return agent.Preview{}, errors.New("agent service is not ready")
	}
	if !a.core.Status().Running {
		return agent.Preview{}, errors.New("core is not running")
	}
	if change.Operation != "set" && change.Operation != "clear" {
		return agent.Preview{}, errors.New("operation must be set or clear")
	}
	if change.Scope != "global" && change.Scope != "profile" && change.Scope != "connection" {
		return agent.Preview{}, errors.New("scope must be global, profile, or connection")
	}
	if err := change.Layer.Validate(); err != nil {
		return agent.Preview{}, err
	}
	active := a.core.ProfileID()
	catalog, err := a.profiles.Load()
	if err != nil {
		return agent.Preview{}, err
	}
	state := a.rewrites.Snapshot()
	revision := state.Revision
	target := active
	var warnings []string
	switch change.Scope {
	case "global":
		if change.Operation == "clear" {
			state.Global = rewrite.Layer{}
		} else {
			state.Global = change.Layer
		}
	case "profile":
		target = change.ProfileID
		found := false
		for _, p := range catalog.Items {
			if p.UID == target {
				found = true
				break
			}
		}
		if !found {
			return agent.Preview{}, errors.New("profile not found")
		}
		if state.Profiles == nil {
			state.Profiles = make(map[string]rewrite.Layer)
		}
		if change.Operation == "clear" {
			delete(state.Profiles, target)
		} else {
			state.Profiles[target] = change.Layer
		}
		if target != active {
			warnings = append(warnings, "The profile is inactive; changes take effect when it is activated.")
		}
	case "connection":
		if change.ConnectionID == "" {
			return agent.Preview{}, errors.New("connection_id is required")
		}
		var kept []rewrite.Connection
		for _, item := range state.Connections {
			if item.ID != change.ConnectionID {
				kept = append(kept, item)
			}
		}
		state.Connections = kept
		if change.Operation == "set" {
			if change.TTLSeconds < 1 || change.TTLSeconds > 86400 {
				return agent.Preview{}, errors.New("ttl_seconds must be between 1 and 86400")
			}
			var match *conn.Item
			items, _, _ := a.core.Connections()
			for i := range items {
				if items[i].ID == change.ConnectionID {
					match = &items[i]
					break
				}
			}
			if match == nil {
				return agent.Preview{}, errors.New("active connection not found")
			}
			rule, err := connectionRule(*match, change.Policy)
			if err != nil {
				return agent.Preview{}, err
			}
			state.Connections = append(state.Connections, rewrite.Connection{ID: change.ConnectionID, ProfileID: active, Rule: rule, ExpiresAt: time.Now().UTC().Add(time.Duration(change.TTLSeconds) * time.Second)})
			warnings = append(warnings, "Rules affect new connections sharing the destination, port, network and source IP; other matching connections can also be affected.", "Existing sockets are not rerouted. Closing the selected connection is optional and does not guarantee reconnection.")
		}
	}
	if a.core.Status().Mode != "rule" {
		warnings = append(warnings, "The core is not in rule mode, so rule changes will not control routing until rule mode is selected.")
	}
	if err := state.Validate(); err != nil {
		return agent.Preview{}, err
	}
	current := a.rewrites.Snapshot()
	before, after, hashes, err := a.previewSources(catalog.Items, current, state, target, change.Scope == "global")
	if err != nil {
		return agent.Preview{}, err
	}
	var token [24]byte
	if _, err = rand.Read(token[:]); err != nil {
		return agent.Preview{}, err
	}
	id := hex.EncodeToString(token[:])
	if a.agentProposals == nil {
		a.agentProposals = make(map[string]agentProposal)
	}
	now := time.Now()
	for k, p := range a.agentProposals {
		if !p.expires.After(now) {
			delete(a.agentProposals, k)
		}
	}
	if len(a.agentProposals) >= 32 {
		return agent.Preview{}, errors.New("too many pending proposals")
	}
	expires := now.Add(2 * time.Minute)
	for _, c := range state.Connections {
		if c.ExpiresAt.After(now) && c.ExpiresAt.Before(expires) {
			expires = c.ExpiresAt
		}
	}
	a.agentProposals[id] = agentProposal{change: change, state: state, revision: revision, activeProfile: active, sources: hashes, expires: expires}
	return agent.Preview{ProposalID: id, Revision: revision, ActiveProfile: active, TargetProfile: target, RulesBefore: before, RulesAfter: after, Warnings: warnings, ExpiresAt: expires}, nil
}

// previewSources validates the whole effective config for the selected profile.
// A global change is also checked against every installed subscription.
func (a *App) previewSources(items []profile.CatalogItem, before, after rewrite.State, target string, all bool) ([]string, []string, map[string][32]byte, error) {
	active := a.core.ProfileID()
	sources := map[string]string{active: filepath.Join(a.dir, "config.yaml")}
	for _, item := range items {
		if item.UID == active {
			continue
		}
		if all || item.UID == target {
			file, err := profileFilePath(a.dir, item.File)
			if err != nil {
				return nil, nil, nil, err
			}
			sources[item.UID] = file
		}
	}
	var beforeRules, afterRules []string
	foundTarget := false
	hashes := make(map[string][32]byte, len(sources))
	catalogPath := filepath.Join(a.dir, "profiles.json")
	if data, err := os.ReadFile(catalogPath); err == nil {
		hashes[catalogPath] = sha256.Sum256(data)
	} else if errors.Is(err, os.ErrNotExist) {
		hashes[catalogPath] = [32]byte{}
	} else {
		return nil, nil, nil, err
	}
	if a.kernelOptions != nil {
		path := filepath.Join(a.dir, "kernel-options.json")
		if data, err := os.ReadFile(path); err == nil {
			hashes[path] = sha256.Sum256(data)
		} else if errors.Is(err, os.ErrNotExist) {
			hashes[path] = [32]byte{}
		} else {
			return nil, nil, nil, err
		}
	}
	for id, path := range sources {
		base, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, err
		}
		hashes[path] = sha256.Sum256(base)
		if id != active {
			base = profile.EnsureMixedPort(base, 7897)
		}
		base, err = a.applyProfileTUN(base)
		if err != nil {
			return nil, nil, nil, err
		}
		base, err = a.applyProfileDNS(base, id)
		if err != nil {
			return nil, nil, nil, err
		}
		_, oldRules, err := rewrite.Compose(base, before, id, time.Now())
		if err != nil {
			return nil, nil, nil, err
		}
		effective, newRules, err := rewrite.Compose(base, after, id, time.Now())
		if err != nil {
			return nil, nil, nil, err
		}
		if a.kernelOptions != nil {
			effective, err = kernelopts.Compose(effective, a.kernelOptions.Snapshot())
			if err != nil {
				return nil, nil, nil, err
			}
		}
		if _, err = executor.ParseWithBytes(effective); err != nil {
			return nil, nil, nil, fmt.Errorf("profile %q: %w", id, err)
		}
		if id == target {
			beforeRules, afterRules, foundTarget = oldRules, newRules, true
		}
	}
	if !foundTarget {
		return nil, nil, nil, errors.New("target configuration is unavailable")
	}
	return beforeRules, afterRules, hashes, nil
}

func (a *App) agentApply(id string) (agent.ApplyResult, error) {
	p, ok := a.agentProposals[id]
	if !ok || !p.expires.After(time.Now()) {
		delete(a.agentProposals, id)
		return agent.ApplyResult{}, errors.New("proposal missing or expired; preview again")
	}
	delete(a.agentProposals, id)
	if a.core.ProfileID() != p.activeProfile || a.rewrites.Snapshot().Revision != p.revision {
		return agent.ApplyResult{}, errors.New("configuration changed; preview again")
	}
	if !a.core.Status().Running {
		return agent.ApplyResult{}, errors.New("core is not running")
	}
	for path, expected := range p.sources {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && expected == ([32]byte{}) {
			continue
		}
		if err != nil || sha256.Sum256(data) != expected {
			return agent.ApplyResult{}, errors.New("source configuration changed; preview again")
		}
	}
	if p.change.Scope == "connection" && p.change.Operation == "set" {
		items, _, _ := a.core.Connections()
		found := false
		for _, item := range items {
			if item.ID != p.change.ConnectionID {
				continue
			}
			rule, err := connectionRule(item, p.change.Policy)
			if err != nil {
				return agent.ApplyResult{}, err
			}
			for _, candidate := range p.state.Connections {
				if candidate.ID == item.ID && candidate.Rule == rule {
					found = true
				}
			}
		}
		if !found {
			return agent.ApplyResult{}, errors.New("connection changed or closed; preview again")
		}
	}
	old := a.rewrites.Snapshot()
	saved, err := a.rewrites.Replace(p.state, p.revision)
	if err != nil {
		return agent.ApplyResult{}, err
	}
	active := p.change.Scope != "profile" || p.change.ProfileID == p.activeProfile
	if active {
		if err = a.core.Reload(); err != nil {
			_, restoreErr := a.rewrites.Replace(old, saved.Revision)
			if restoreErr == nil {
				restoreErr = a.core.Reload()
			}
			if restoreErr != nil {
				return agent.ApplyResult{}, errors.Join(err, fmt.Errorf("restore previous rules: %w", restoreErr))
			}
			return agent.ApplyResult{}, err
		}
	}
	result := agent.ApplyResult{Revision: saved.Revision, Active: active}
	if p.change.Scope == "connection" && p.change.Operation == "set" && p.change.CloseExisting {
		closed, err := a.core.CloseExistingConnection(p.change.ConnectionID)
		if err != nil {
			result.Warnings = append(result.Warnings, "rule applied, but closing the original connection failed: "+err.Error())
		} else {
			result.ClosedConnection = closed
			if !closed {
				result.Warnings = append(result.Warnings, "rule applied, but the original connection had already closed")
			}
		}
	}
	if a.model != nil {
		a.model.Notice = fmt.Sprintf("Agent 已应用%s规则（版本 %d）", p.change.Scope, saved.Revision)
		a.refreshHome()
	}
	return result, nil
}

func connectionRule(item conn.Item, policy string) (string, error) {
	valid := func(s string) bool { return s != "" && !strings.ContainsAny(s, ",()\r\n\x00") }
	if !valid(policy) || strings.TrimSpace(policy) != policy {
		return "", errors.New("invalid policy name")
	}
	network := strings.ToUpper(item.Network)
	if network != "TCP" && network != "UDP" {
		return "", errors.New("connection network must be TCP or UDP")
	}
	parts := []string{"(NETWORK," + network + ")"}
	if host := strings.TrimSpace(item.Host); host != "" {
		if !valid(host) {
			return "", errors.New("unsupported connection hostname")
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			parts = append(parts, ipRule(ip))
		} else {
			parts = append(parts, "(DOMAIN,"+host+")")
		}
	} else if ip, err := netip.ParseAddr(item.DestinationIP); err == nil {
		parts = append(parts, ipRule(ip))
	} else {
		return "", errors.New("connection has no usable destination")
	}
	port, err := strconv.Atoi(item.DestinationPort)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("connection has no usable destination port")
	}
	parts = append(parts, fmt.Sprintf("(DST-PORT,%d)", port))
	source, err := netip.ParseAddr(item.SourceIP)
	if err != nil {
		return "", errors.New("connection has no usable source IP")
	}
	parts = append(parts, "(SRC-IP-CIDR,"+netip.PrefixFrom(source, source.BitLen()).String()+")")
	return "AND,(" + strings.Join(parts, ",") + ")," + policy, nil
}

func ipRule(ip netip.Addr) string {
	kind := "IP-CIDR"
	if ip.Is6() {
		kind = "IP-CIDR6"
	}
	return "(" + kind + "," + netip.PrefixFrom(ip, ip.BitLen()).String() + ")"
}

func decodeAgentArgs(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	return json.Unmarshal(raw, out)
}
