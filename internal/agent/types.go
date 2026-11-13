package agent

import (
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}
type Status struct {
	Running       bool          `json:"running"`
	Mode          string        `json:"mode"`
	ActiveProfile string        `json:"active_profile,omitempty"`
	Revision      uint64        `json:"revision"`
	Profiles      []Profile     `json:"profiles"`
	Connections   []conn.Item   `json:"connections"`
	Overrides     rewrite.State `json:"overrides"`
}

type Change struct {
	Scope         string        `json:"scope" jsonschema:"global, profile, or connection"`
	Operation     string        `json:"operation" jsonschema:"set or clear"`
	ProfileID     string        `json:"profile_id,omitempty" jsonschema:"profile id for profile scope"`
	Layer         rewrite.Layer `json:"layer,omitempty" jsonschema:"rule changes for global or profile scope"`
	ConnectionID  string        `json:"connection_id,omitempty" jsonschema:"active connection id for connection scope"`
	Policy        string        `json:"policy,omitempty" jsonschema:"existing proxy policy for connection scope"`
	TTLSeconds    int           `json:"ttl_seconds,omitempty" jsonschema:"connection override lifetime in seconds, between 1 and 86400"`
	CloseExisting bool          `json:"close_existing,omitempty" jsonschema:"close the selected existing connection after applying a connection override"`
}

type Preview struct {
	ProposalID    string    `json:"proposal_id"`
	Revision      uint64    `json:"revision"`
	ActiveProfile string    `json:"active_profile,omitempty"`
	TargetProfile string    `json:"target_profile,omitempty"`
	RulesBefore   []string  `json:"rules_before"`
	RulesAfter    []string  `json:"rules_after"`
	Warnings      []string  `json:"warnings,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type ApplyArgs struct {
	ProposalID string `json:"proposal_id" jsonschema:"proposal id returned by preview"`
}
type ApplyResult struct {
	Revision         uint64   `json:"revision"`
	Active           bool     `json:"active"`
	ClosedConnection bool     `json:"closed_connection"`
	Warnings         []string `json:"warnings,omitempty"`
}
