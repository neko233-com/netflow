//go:build darwin

package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/neko233-com/netflow/internal/coreipc"
)

func workerPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "..", "Resources", "netflow-kernel-worker")
}

func canLaunchTUNWorker() bool {
	if tunCIBlocked() {
		return false
	}
	info, err := os.Stat(workerPath())
	return err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0
}

func launchTUNWorker(ctx context.Context) (coreEngine, error) {
	return coreipc.LaunchDarwin(ctx, workerPath())
}
