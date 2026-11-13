//go:build windows && integration

package coreipc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

// TerminateWorkerForIntegration terminates only the child retained by this
// client. The caller must first enforce the isolated guest safety checks.
func TerminateWorkerForIntegration(c *Client) error {
	if os.Getenv("NETFLOW_WINDOWS_VM") != "1" || c == nil || c.workerPID == 0 {
		return errors.New("isolated worker required")
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	h, err := launchWithVerb(filepath.Join(systemDir, "taskkill.exe"), []string{"/PID", strconv.FormatUint(uint64(c.workerPID), 10), "/F"}, "runas")
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	state, err := windows.WaitForSingleObject(h, 30000)
	if err != nil {
		return err
	}
	if state != windows.WAIT_OBJECT_0 {
		return errors.New("elevated taskkill timed out")
	}
	var exit uint32
	if err := windows.GetExitCodeProcess(h, &exit); err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("elevated taskkill failed: %d", exit)
	}
	return nil
}
