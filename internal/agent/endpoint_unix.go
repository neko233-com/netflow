//go:build !windows

package agent

import "os"

func createPrivateEndpoint(dir, prefix string) (*os.File, error) {
	return os.CreateTemp(dir, prefix+"*.json")
}
