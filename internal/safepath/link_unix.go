//go:build unix

package safepath

import (
	"errors"
	"os"
	"syscall"
)

func requireSingleLink(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("lock file has multiple or unknown hard links")
	}
	return nil
}
