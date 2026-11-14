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
