//go:build !windows

package app

import (
	"context"
	"errors"
)

func canLaunchTUNWorker() bool { return false }
func launchTUNWorker(context.Context) (coreEngine, error) {
	return nil, errors.New("此平台的特权内核尚不可用")
}
