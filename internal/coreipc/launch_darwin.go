//go:build darwin

package coreipc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func darwinPeer(c *net.UnixConn) (uint32, int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var uid uint32
	var pid int
	var inner error
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if inner != nil {
			return
		}
		uid = cred.Uid
		pid, inner = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, 0, err
	}
	return uid, pid, inner
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// LaunchDarwin authenticates the root peer using kernel-provided credentials;
// the worker separately verifies the desktop PID and UID before serving RPC.
func LaunchDarwin(ctx context.Context, exe string) (*Client, error) {
	if !filepath.IsAbs(exe) {
		return nil, errors.New("kernel executable path must be absolute")
	}
	info, err := os.Stat(exe)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, errors.New("kernel executable is not executable")
	}
	dir, err := os.MkdirTemp("/tmp", "netflow-ipc-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	command := "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin " + shellQuote(exe) + " --socket " + shellQuote(path) + " --parent " + strconv.Itoa(os.Getpid()) + " --uid " + strconv.Itoa(os.Getuid())
	script := "on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run"
	cmd := exec.Command("/usr/bin/osascript", "-e", script, command)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	type result struct {
		conn *net.UnixConn
		err  error
	}
	accepted := make(chan result, 1)
	go func() { c, e := listener.AcceptUnix(); accepted <- result{c, e} }()
	var conn *net.UnixConn
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = listener.Close()
		r := <-accepted
		if r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, ctx.Err()
	case err = <-done:
		_ = listener.Close()
		r := <-accepted
		if r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, fmt.Errorf("特权内核授权失败: %v %s", err, strings.TrimSpace(stderr.String()))
	case r := <-accepted:
		if r.err != nil {
			_ = cmd.Process.Kill()
			return nil, r.err
		}
		conn = r.conn
	}
	uid, _, err := darwinPeer(conn)
	if err != nil || uid != 0 {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		return nil, errors.New("特权内核连接身份验证失败")
	}
	client, err := NewClient(conn)
	if err != nil {
		_ = conn.Close()
		_ = cmd.Process.Kill()
		return nil, err
	}
	client.closeHook = func() error {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("特权内核退出失败: %w %s", err, strings.TrimSpace(stderr.String()))
			}
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("特权内核未在规定时间内退出")
		}
	}
	return client, nil
}

func DialDarwinParent(ctx context.Context, path string, expectedPID int, expectedUID uint32) (net.Conn, error) {
	if !filepath.IsAbs(path) || expectedPID <= 0 || expectedPID == os.Getpid() {
		return nil, errors.New("invalid parent identity")
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("invalid local socket")
	}
	uid, pid, err := darwinPeer(u)
	if err != nil || pid != expectedPID || uid != expectedUID {
		_ = conn.Close()
		return nil, errors.New("kernel socket server identity mismatch")
	}
	return conn, nil
}
