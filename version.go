// Package netflow exposes metadata shared by the application and its tools.
package netflow

import (
	_ "embed"
	"encoding/json"
)

//go:embed mygo.json
var manifest []byte

// Version is the version embedded from the same manifest used by packaging.
func Version() string {
	var data struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(manifest, &data) != nil || data.Version == "" {
		return "unknown"
	}
	return data.Version
}
