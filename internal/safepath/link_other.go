//go:build !windows && !unix

package safepath

import (
	"errors"
	"os"
)

func requireSingleLink(*os.File) error {
	return errors.New("lock file link count is unavailable on this platform")
}
