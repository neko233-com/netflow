//go:build !windows

package safepath

import "path/filepath"

// Canonical resolves a filesystem object and its symbolic links.
func Canonical(path string) (string, error) { return filepath.EvalSymlinks(path) }
