//go:build windows

package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Canonical resolves a filesystem object, including junctions and 8.3 names.
func Canonical(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || int(n) >= len(buffer) {
		return "", errors.New("resolved path is too long")
	}
	result := windows.UTF16ToString(buffer[:n])
	if strings.HasPrefix(strings.ToUpper(result), `\\?\UNC\`) {
		result = `\\` + result[8:]
	} else if strings.HasPrefix(result, `\\?\`) {
		result = result[4:]
	}
	return filepath.Clean(result), nil
}
