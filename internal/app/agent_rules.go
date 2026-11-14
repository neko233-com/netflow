package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/safepath"
	"github.com/neko233-com/netflow/internal/tun"
	"github.com/neko233-com/netflow/internal/validation"
)

type agentProposal struct {
	change        agent.Change
	state         rewrite.State
	revision      uint64
	activeProfile string
	sources       map[string][32]byte
	expires       time.Time
	tunEnabled    bool
	tunSetting    bool
	mode          string
	options       *kernelopts.Options
	before, after []string
	ruleBytes     int
	chain         *activeChain
}

const maxPreviewRuleMemory = 64 << 20
const maxPreviewPageBytes = 256 << 10

// The bridge and agent clients have finite response limits. Pages are bounded
// by both rule count and encoded JSON bytes, including escaped characters.
func previewRulePage(rules []string, offset, limit int) (agent.PreviewRulesResult, error) {
	if offset < 0 || limit < 0 || limit > 500 {
		return agent.PreviewRulesResult{}, errors.New("offset must be nonnegative and limit must be at most 500")
	}
	if limit == 0 {
		limit = 100
	}
	if offset > len(rules) {
		offset = len(rules)
	}
	out := agent.PreviewRulesResult{Total: len(rules), Offset: offset, NextOffset: offset, Rules: []string{}}
	encodedBytes := 2
	for out.NextOffset < len(rules) && len(out.Rules) < limit {
		item := rules[out.NextOffset]
		encoded, err := json.Marshal(item)
		if err != nil {
			return agent.PreviewRulesResult{}, err
		}
		if len(encoded)+2 > maxPreviewPageBytes {
			return agent.PreviewRulesResult{}, errors.New("one rule exceeds the preview page size limit")
		}
		extra := len(encoded)
		if len(out.Rules) > 0 {
			extra++
		}
		if encodedBytes+extra > maxPreviewPageBytes {
			break
		}
		encodedBytes += extra
		out.Rules = append(out.Rules, item)
		out.NextOffset++
	}
	return out, nil
}

func previewRuleFootprint(lists ...[]string) (int, error) {
	total := 0
	for _, list := range lists {
		for _, rule := range list {
			if len(rule) > maxPreviewPageBytes/6 {
				encoded, err := json.Marshal(rule)
				if err != nil || len(encoded)+2 > maxPreviewPageBytes {
					return 0, errors.New("one rule exceeds the preview page size limit")
				}
			}
			if len(rule) > maxPreviewRuleMemory-total-16 {
				return 0, errors.New("preview rules exceed the in-memory size limit")
			}
			total += len(rule) + 16
		}
	}
	return total, nil
}

func (a *App) agentPreviewRules(in agent.PreviewRulesArgs) (agent.PreviewRulesResult, error) {
	p, ok := a.agentProposals[in.ProposalID]
	if !ok || !p.expires.After(time.Now()) {
		delete(a.agentProposals, in.ProposalID)
		return agent.PreviewRulesResult{}, errors.New("proposal missing or expired; preview again")
	}
	switch in.Stage {
	case "before":
		return previewRulePage(p.before, in.Offset, in.Limit)
	case "after":
		return previewRulePage(p.after, in.Offset, in.Limit)
	default:
		return agent.PreviewRulesResult{}, errors.New("stage must be before or after")
	}
}

func (a *App) pruneExpiredProposals(now time.Time) {
	for id, proposal := range a.agentProposals {
		if !proposal.expires.After(now) {
			delete(a.agentProposals, id)
		}
	}
	for id, preview := range a.agentScriptPreviews {
		if !preview.expires.After(now) {
			delete(a.agentScriptPreviews, id)
		}
	}
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
	page, pageErr := connectionPage(connections, agent.ConnectionsArgs{})
	out := agent.Status{Running: st.Running, Headless: a.headless, TUN: st.TUN, TUNPending: a.tunBusy, TUNError: a.tunLastError, GeoPending: a.geoBusy, GeoError: a.geoLastError, GeoRestart: a.geoRestart, TUNStacks: tun.SupportedStacks(), Mode: st.Mode, ActiveProfile: a.core.ProfileID(), Revision: a.rewrites.Snapshot().Revision, Connections: page.Connections, ConnectionsTotal: len(connections), ConnectionsTruncated: pageErr != nil || page.NextOffset < len(connections), Overrides: a.rewrites.Snapshot()}
	if pageErr != nil {
		out.Connections = []conn.Item{}
		out.ConnectionsWarning = "A connection is too large to display; inspect it in the application."
	}
	out.RewriteWarning = a.rewriteWarning
	if a.rewrites.CheckCurrent() != nil && out.RewriteWarning == "" {
		out.RewriteWarning = "Rule file changed or is unreadable; inspect it and restart NetFlow."
	}
	if a.kernelOptions != nil && a.kernelOptions.CheckCurrent() != nil {
		out.KernelOptionsWarning = "Kernel options file changed or is unreadable; inspect it and restart NetFlow."
	}
	if a.checkSettingsCurrent() != nil {
		out.SettingsWarning = "Settings file changed or is unreadable; inspect it and restart NetFlow."
	}
	if source, ok := a.core.(interface{ CacheWarning() string }); ok {
		out.ProviderCacheWarning = source.CacheWarning()
	}
	profilePage, profileErr := profilePage(catalog, out.ActiveProfile, agent.PageArgs{})
	out.ProfilesTotal = len(catalog.Items)
	out.ProfilesTruncated = profileErr != nil || profilePage.NextOffset < len(catalog.Items)
	if profileErr != nil {
		out.Profiles = []agent.Profile{}
		out.ProfilesWarning = "A profile is too large to display; inspect it in the application."
	} else {
		out.Profiles = profilePage.Profiles
	}
	return out, nil
}

type previewDraft struct {
	change         agent.Change
	state          rewrite.State
	revision       uint64
	active, target string
	status         core.Status
	tunSetting     bool
	options        *kernelopts.Options
	before, after  []string
	hashes         map[string][32]byte
	warnings       []string
	configs        []validation.Config
	chain          *activeChain
}

func (a *App) agentPreview(change agent.Change) (agent.Preview, error) {
	draft, err := a.prepareAgentPreview(change)
	if err != nil {
		return agent.Preview{}, err
	}
	checked, err := validateConfigurations(context.Background(), a.dir, draft.configs)
	if err != nil {
		return agent.Preview{}, err
	}
	if err := a.verifyDraftSources(draft, checked); err != nil {
		return agent.Preview{}, err
	}
	return a.finishAgentPreview(draft, checked)
}

func (a *App) prepareAgentPreview(change agent.Change) (previewDraft, error) {
	if a.rewrites == nil || a.core == nil || a.profiles == nil {
		return previewDraft{}, errors.New("agent service is not ready")
	}
	if err := a.rewrites.CheckCurrent(); err != nil {
		return previewDraft{}, err
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return previewDraft{}, err
		}
	}
	status := a.core.Status()
	if !status.Running {
		return previewDraft{}, errors.New("core is not running")
	}
	if a.tunBusy {
		return previewDraft{}, errors.New("TUN transition in progress; preview again after it completes")
	}
	if change.Operation != "set" && change.Operation != "clear" {
		return previewDraft{}, errors.New("operation must be set or clear")
	}
	if change.Scope != "global" && change.Scope != "profile" && change.Scope != "connection" {
		return previewDraft{}, errors.New("scope must be global, profile, or connection")
	}
	if err := change.Layer.Validate(); err != nil {
		return previewDraft{}, err
	}
	active := a.core.ProfileID()
	catalog, catalogHash, err := a.profiles.LoadSnapshot()
	if err != nil {
		return previewDraft{}, err
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
			return previewDraft{}, errors.New("profile not found")
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
			return previewDraft{}, errors.New("connection_id is required")
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
				return previewDraft{}, errors.New("ttl_seconds must be between 1 and 86400")
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
				return previewDraft{}, errors.New("active connection not found")
			}
			rule, err := connectionRule(*match, change.Policy)
			if err != nil {
				return previewDraft{}, err
			}
			state.Connections = append(state.Connections, rewrite.Connection{ID: change.ConnectionID, ProfileID: active, Rule: rule, ExpiresAt: time.Now().UTC().Add(time.Duration(change.TTLSeconds) * time.Second)})
			warnings = append(warnings, "Rules affect new connections sharing the destination, port, network and source IP; other matching connections can also be affected.", "Existing sockets are not rerouted. Closing the selected connection is optional and does not guarantee reconnection.")
		}
	}
	if status.Mode != "rule" {
		warnings = append(warnings, "The core is not in rule mode, so rule changes will not control routing until rule mode is selected.")
	}
	if err := state.Validate(); err != nil {
		return previewDraft{}, err
	}
	current := a.rewrites.Snapshot()
	var options *kernelopts.Options
	if a.kernelOptions != nil {
		value := a.kernelOptions.Snapshot()
		options = &value
	}
	var configs []validation.Config
	chain := a.chain.Load()
	before, after, hashes, err := a.previewSources(catalog, catalogHash, options, current, state, target, change.Scope == "global", &configs, chain)
	if err != nil {
		return previewDraft{}, err
	}
	return previewDraft{change: change, state: state, revision: revision, active: active, target: target, status: status, tunSetting: a.settings.TUN, options: options, before: before, after: after, hashes: hashes, warnings: warnings, configs: configs, chain: chain}, nil
}

func (a *App) verifyDraftSources(draft previewDraft, checked validation.Result) error {
	for path, hash := range checked.Sources {
		if previous, ok := draft.hashes[path]; ok && previous != hash {
			return errors.New("source changed during validation")
		}
		draft.hashes[path] = hash
	}
	return a.checkAgentSources(draft.hashes)
}

func (a *App) finishAgentPreview(draft previewDraft, checked validation.Result) (agent.Preview, error) {
	if err := a.rewrites.CheckCurrent(); err != nil {
		return agent.Preview{}, err
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return agent.Preview{}, err
		}
	}
	status := a.core.Status()
	if !status.Running || a.tunBusy || a.core.ProfileID() != draft.active || a.rewrites.Snapshot().Revision != draft.revision || status.TUN != draft.status.TUN || status.Mode != draft.status.Mode || a.settings.TUN != draft.tunSetting || a.chain.Load() != draft.chain {
		return agent.Preview{}, errors.New("configuration or network state changed; preview again")
	}
	if (a.kernelOptions == nil) != (draft.options == nil) || (draft.options != nil && !reflect.DeepEqual(a.kernelOptions.Snapshot(), *draft.options)) {
		return agent.Preview{}, errors.New("kernel options changed; preview again")
	}
	draft.warnings = append(draft.warnings, checked.Warnings...)
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return agent.Preview{}, err
	}
	id := hex.EncodeToString(token[:])
	if a.agentProposals == nil {
		a.agentProposals = make(map[string]agentProposal)
	}
	now := time.Now()
	for _, c := range draft.state.Connections {
		if !c.ExpiresAt.After(now) {
			return agent.Preview{}, errors.New("connection rule expired during validation; preview again")
		}
	}
	a.pruneExpiredProposals(now)
	if len(a.agentProposals) >= 32 {
		return agent.Preview{}, errors.New("too many pending proposals")
	}
	ruleBytes, err := previewRuleFootprint(draft.before, draft.after)
	if err != nil {
		return agent.Preview{}, err
	}
	used := 0
	for _, proposal := range a.agentProposals {
		used += proposal.ruleBytes
	}
	for _, preview := range a.agentScriptPreviews {
		used += preview.bytes
	}
	if ruleBytes > maxPreviewRuleMemory-used {
		return agent.Preview{}, errors.New("pending preview rules exceed the in-memory size limit; apply, cancel or wait for existing previews")
	}
	before, err := previewRulePage(draft.before, 0, 100)
	if err != nil {
		return agent.Preview{}, err
	}
	after, err := previewRulePage(draft.after, 0, 100)
	if err != nil {
		return agent.Preview{}, err
	}
	if before.NextOffset < before.Total || after.NextOffset < after.Total {
		draft.warnings = append(draft.warnings, "Preview contains only the first page of rules; use preview-rules to inspect remaining pages before applying.")
	}
	expires := now.Add(2 * time.Minute)
	for _, c := range draft.state.Connections {
		if c.ExpiresAt.After(now) && c.ExpiresAt.Before(expires) {
			expires = c.ExpiresAt
		}
	}
	a.agentProposals[id] = agentProposal{change: draft.change, state: draft.state, revision: draft.revision, activeProfile: draft.active, sources: draft.hashes, expires: expires, tunEnabled: status.TUN, tunSetting: draft.tunSetting, mode: status.Mode, options: draft.options, before: draft.before, after: draft.after, ruleBytes: ruleBytes, chain: draft.chain}
	return agent.Preview{ProposalID: id, Revision: draft.revision, ActiveProfile: draft.active, TargetProfile: draft.target, RulesBefore: before.Rules, RulesAfter: after.Rules, RulesBeforeTotal: before.Total, RulesAfterTotal: after.Total, RulesBeforeTruncated: before.NextOffset < before.Total, RulesAfterTruncated: after.NextOffset < after.Total, Warnings: draft.warnings, ExpiresAt: expires}, nil
}

// previewSources validates the whole effective config for the selected profile.
// A global change is also checked against every installed subscription.
func (a *App) previewSources(catalog profile.File, catalogHash [32]byte, options *kernelopts.Options, before, after rewrite.State, target string, all bool, outConfigs *[]validation.Config, chain *activeChain) ([]string, []string, map[string][32]byte, error) {
	active := a.core.ProfileID()
	sources := map[string]string{active: filepath.Join(a.dir, "config.yaml")}
	relativeProfiles := map[string]string{}
	for _, item := range catalog.Items {
		if item.UID == active {
			continue
		}
		if all || item.UID == target {
			file, err := profileFilePath(a.dir, item.File)
			if err != nil {
				return nil, nil, nil, err
			}
			sources[item.UID] = file
			relativeProfiles[item.UID] = item.File
		}
	}
	var beforeRules, afterRules []string
	var configs []validation.Config
	foundTarget := false
	hashes := make(map[string][32]byte, len(sources))
	catalogPath := filepath.Join(a.dir, "profiles.json")
	hashes[catalogPath] = catalogHash
	if a.kernelOptions != nil {
		path := filepath.Join(a.dir, "kernel-options.json")
		if data, err := safepath.ReadFile(a.dir, "kernel-options.json"); err == nil {
			hashes[path] = sha256.Sum256(data)
		} else if errors.Is(err, os.ErrNotExist) {
			hashes[path] = [32]byte{}
		} else {
			return nil, nil, nil, err
		}
	}
	for id, path := range sources {
		var base []byte
		var err error
		if rel, ok := relativeProfiles[id]; ok {
			base, path, err = readProfileFile(a.dir, rel)
		} else {
			base, err = safepath.ReadFile(a.dir, "config.yaml")
		}
		if err != nil {
			return nil, nil, nil, err
		}
		hashes[path] = sha256.Sum256(base)
		if id != active {
			base = profile.EnsureMixedPort(base, 7897)
		}
		var extensionSources map[string][32]byte
		base, extensionSources, err = a.composeVergeExtensionsFromCatalog(base, id, catalog)
		if err != nil {
			return nil, nil, nil, err
		}
		for path, hash := range extensionSources {
			if previous, exists := hashes[path]; exists && previous != hash {
				return nil, nil, nil, errors.New("Verge 存档在预览期间发生变化，请重试")
			}
			hashes[path] = hash
		}
		base, err = a.applyProfileTUN(base)
		if err != nil {
			return nil, nil, nil, err
		}
		base, err = composeProfileDNSFromCatalog(base, id, catalog)
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
		if options != nil {
			effective, err = kernelopts.Compose(effective, *options)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		effective, err = composeActiveChain(effective, id, chain)
		if err != nil {
			return nil, nil, nil, err
		}
		configs = append(configs, validation.Config{ID: id, Body: effective})
		if id == target {
			beforeRules, afterRules, foundTarget = oldRules, newRules, true
		}
	}
	if !foundTarget {
		return nil, nil, nil, errors.New("target configuration is unavailable")
	}
	if outConfigs != nil {
		*outConfigs = configs
	}
	return beforeRules, afterRules, hashes, nil
}

func (a *App) checkAgentSources(sources map[string][32]byte) error {
	root, err := os.OpenRoot(a.dir)
	if err != nil {
		return errors.New("source configuration changed; preview again")
	}
	defer root.Close()
	for path, expected := range sources {
		actual, err := validation.HashSource(root, a.dir, path)
		if errors.Is(err, os.ErrNotExist) && expected == ([32]byte{}) {
			continue
		}
		if err != nil || actual != expected {
			kind := "configuration"
			rel, _ := filepath.Rel(a.dir, path)
			switch {
			case strings.HasPrefix(filepath.ToSlash(rel), "verge-providers/"):
				kind = "imported provider"
			case strings.HasPrefix(filepath.ToSlash(rel), "verge-imports/"):
				kind = "import archive"
			case strings.HasPrefix(filepath.ToSlash(rel), "profiles/"):
				kind = "profile"
			case strings.EqualFold(filepath.Ext(path), ".mmdb"), strings.EqualFold(filepath.Ext(path), ".dat"), strings.EqualFold(filepath.Ext(path), ".db"):
				kind = "geodata"
			}
			reason := "content changed"
			if errors.Is(err, os.ErrNotExist) {
				reason = "missing"
			} else if err != nil {
				reason = "unreadable"
			}
			return fmt.Errorf("source configuration changed (%s: %s); preview again", kind, reason)
		}
	}
	return nil
}

func (a *App) agentApply(id string) (agent.ApplyResult, error) {
	p, ok := a.agentProposals[id]
	if !ok || !p.expires.After(time.Now()) {
		delete(a.agentProposals, id)
		return agent.ApplyResult{}, errors.New("proposal missing or expired; preview again")
	}
	delete(a.agentProposals, id)
	if a.core.ProfileID() != p.activeProfile || a.rewrites.Snapshot().Revision != p.revision || a.chain.Load() != p.chain {
		return agent.ApplyResult{}, errors.New("configuration changed; preview again")
	}
	status := a.core.Status()
	if !status.Running {
		return agent.ApplyResult{}, errors.New("core is not running")
	}
	if a.tunBusy || status.TUN != p.tunEnabled || status.Mode != p.mode || a.settings.TUN != p.tunSetting {
		return agent.ApplyResult{}, errors.New("network state changed; preview again")
	}
	if (a.kernelOptions == nil) != (p.options == nil) || (p.options != nil && !reflect.DeepEqual(a.kernelOptions.Snapshot(), *p.options)) {
		return agent.ApplyResult{}, errors.New("kernel options changed; preview again")
	}
	if a.kernelOptions != nil {
		if err := a.kernelOptions.CheckCurrent(); err != nil {
			return agent.ApplyResult{}, err
		}
	}
	if err := a.checkAgentSources(p.sources); err != nil {
		return agent.ApplyResult{}, err
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
