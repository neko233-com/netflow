//go:build windows

package safepath

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func requireSingleLink(f *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return errors.New("lock file has multiple hard links")
	}
	return nil
}
