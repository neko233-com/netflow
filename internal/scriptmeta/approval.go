// Package scriptmeta defines persisted script approval metadata without
// retaining subscription contents.
package scriptmeta

import "time"

// Approval identifies the exact script inputs and immutable output previously
// reviewed by a caller. Runtime users must independently recheck the inputs.
type Approval struct {
	Version       int       `json:"version"`
	Archive       string    `json:"archive"`
	VergeUID      string    `json:"verge_uid"`
	Global        bool      `json:"global"`
	Profile       bool      `json:"profile"`
	Clock         time.Time `json:"clock"`
	BaseSHA256    string    `json:"base_sha256"`
	NameSHA256    string    `json:"name_sha256"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	OutputSHA256  string    `json:"output_sha256"`
}

// Previous is the exact script setting before the last committed change.
// An absent Approval represents the previous data-only configuration.
type Previous struct {
	Approval        *Approval             `json:"approval,omitempty"`
	VergeExtensions bool                  `json:"verge_extensions,omitempty"`
	Subscription    *SubscriptionSnapshot `json:"subscription,omitempty"`
}

// SubscriptionSnapshot identifies a retained profile file and its associated
// subscription metadata for an explicitly previewed update rollback. Files
// may contain credentials and must remain private to the configuration root.
type SubscriptionSnapshot struct {
	File    string    `json:"file"`
	URL     string    `json:"url,omitempty"`
	Name    string    `json:"name,omitempty"`
	Updated time.Time `json:"updated,omitempty"`
	Used    int64     `json:"used,omitempty"`
	Total   int64     `json:"total,omitempty"`
	Expire  time.Time `json:"expire,omitempty"`
}
