//go:build windows

package coreipc

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"time"
)

func TestPrivatePipeChild(t *testing.T) {
	path := os.Getenv("NETFLOW_TEST_PIPE")
	if path == "" {
		return
	}
	parent, err := strconv.ParseUint(os.Getenv("NETFLOW_TEST_PARENT"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialParent(ctx, path, uint32(parent))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
}
func TestPrivatePipeChecksProcessIdentity(t *testing.T) {
	for _, reject := range []bool{false, true} {
		l, err := NewPrivateListener()
		if err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestPrivatePipeChild$")
		cmd.Env = append(os.Environ(), "NETFLOW_TEST_PIPE="+l.Path, "NETFLOW_TEST_PARENT="+strconv.Itoa(os.Getpid()))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00004000}
		if err = cmd.Start(); err != nil {
			l.Close()
			t.Fatal(err)
		}
		expected := uint32(cmd.Process.Pid)
		timeout := 5 * time.Second
		if reject {
			expected++
			timeout = 500 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		c, acceptErr := l.AcceptProcess(ctx, expected)
		cancel()
		if reject {
			if acceptErr == nil {
				c.Close()
				t.Error("accepted an untrusted PID")
			}
		} else if acceptErr != nil {
			t.Error(acceptErr)
		} else {
			data := make([]byte, 5)
			if _, err = io.ReadFull(c, data); err != nil || string(data) != "hello" {
				t.Errorf("message %q: %v", data, err)
			}
			c.Close()
		}
		_ = l.Close()
		_ = cmd.Wait()
	}
}

func TestShellLaunchReturnsProcessHandle(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(shellExecuteInfo{}) != 112 {
		t.Fatalf("bad shell info size: %d", unsafe.Sizeof(shellExecuteInfo{}))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := launchWithVerb(exe, []string{"-test.run=^TestPrivatePipeChild$"}, "open")
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if pid, err := windows.GetProcessId(handle); err != nil || pid == 0 {
		t.Fatalf("process id %d: %v", pid, err)
	}
	state, err := windows.WaitForSingleObject(handle, 10000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("worker did not exit: %d %v", state, err)
	}
}
