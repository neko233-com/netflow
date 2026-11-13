//go:build windows

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
	return filepath.Join(filepath.Dir(exe), "netflow-kernel-worker.exe")
}
func canLaunchTUNWorker() bool {
	if tunCIBlocked() {
		return false
	}
	path := workerPath()
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
func launchTUNWorker(ctx context.Context) (coreEngine, error) {
	return coreipc.LaunchWindows(ctx, workerPath())
}
