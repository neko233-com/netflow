//go:build windows

package coreipc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Layout matches SHELLEXECUTEINFOW on Windows. NOCLOSEPROCESS retains the
// child process handle through the pipe handshake, preventing PID reuse.
type shellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	Window     uintptr
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   uintptr
	IDList     uintptr
	Class      *uint16
	ClassKey   uintptr
	HotKey     uint32
	Icon       uintptr
	Process    windows.Handle
}

var shellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func launchElevated(exe string, args []string) (windows.Handle, error) {
	return launchWithVerb(exe, args, "runas")
}

func launchWithVerb(exe string, args []string, action string) (windows.Handle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// ShellExecuteEx may use COM shell extensions; initialize this thread as
	// an STA and balance both S_OK and S_FALSE with CoUninitialize.
	initErr := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)
	if initErr != nil && !errors.Is(initErr, syscall.Errno(1)) {
		return 0, fmt.Errorf("初始化 Windows Shell 失败: %w", initErr)
	}
	defer windows.CoUninitialize()
	if !filepath.IsAbs(exe) {
		return 0, errors.New("kernel executable path must be absolute")
	}
	if st, err := os.Stat(exe); err != nil {
		return 0, err
	} else if !st.Mode().IsRegular() {
		return 0, errors.New("kernel executable is not a regular file")
	}
	verb, err := windows.UTF16PtrFromString(action)
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{Size: uint32(unsafe.Sizeof(shellExecuteInfo{})), Mask: 0x40 | 0x100, Verb: verb, File: file, Parameters: params, Show: 0}
	ok, _, callErr := shellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return 0, fmt.Errorf("启动特权内核失败: %w", callErr)
	}
	if info.Process == 0 {
		return 0, errors.New("特权内核未返回进程句柄")
	}
	return info.Process, nil
}

// LaunchWindows starts a one-shot elevated worker and authenticates both ends
// of its local named pipe. It is not a persistent Windows service.
func LaunchWindows(ctx context.Context, exe string) (*Client, error) {
	l, err := NewPrivateListener()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	proc, err := launchElevated(exe, []string{"--pipe", l.Path, "--parent", strconv.Itoa(os.Getpid())})
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = windows.CloseHandle(proc)
		}
	}()
	pid, err := windows.GetProcessId(proc)
	if err != nil {
		_ = windows.TerminateProcess(proc, 1)
		return nil, err
	}
	c, err := l.AcceptProcess(ctx, pid)
	if err != nil {
		_ = windows.TerminateProcess(proc, 1)
		return nil, fmt.Errorf("特权内核连接失败: %w", err)
	}
	client, err := NewClient(c)
	if err != nil {
		_ = c.Close()
		_ = windows.TerminateProcess(proc, 1)
		return nil, err
	}
	client.workerPID = pid
	client.closeHook = func() error {
		defer windows.CloseHandle(proc)
		state, waitErr := windows.WaitForSingleObject(proc, 10000)
		if waitErr != nil {
			return waitErr
		}
		if state != windows.WAIT_OBJECT_0 {
			return errors.New("特权内核未在规定时间内退出")
		}
		var exitCode uint32
		if err := windows.GetExitCodeProcess(proc, &exitCode); err != nil {
			return err
		}
		if exitCode != 0 {
			return fmt.Errorf("特权内核退出失败，代码 %d", exitCode)
		}
		return nil
	}
	transferred = true
	return client, nil
}
