//go:build windows

package coreipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"

	winio "github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// PrivateListener accepts a connection from one specifically launched child.
// The launcher must retain the child's process handle while checking its PID,
// so Windows cannot recycle that PID during the handshake.
type PrivateListener struct {
	net.Listener
	Path string
}

func NewPrivateListener() (*PrivateListener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	path := `\\.\pipe\netflow-kernel-` + hex.EncodeToString(nonce[:])
	acl := fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", user.User.Sid.String())
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: acl, InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return nil, err
	}
	return &PrivateListener{Listener: l, Path: path}, nil
}

type pipeHandle interface{ Fd() uintptr }

func processID(c net.Conn, client bool) (uint32, error) {
	h, ok := c.(pipeHandle)
	if !ok {
		return 0, errors.New("named pipe handle unavailable")
	}
	var pid uint32
	var err error
	if client {
		err = windows.GetNamedPipeClientProcessId(windows.Handle(h.Fd()), &pid)
	} else {
		err = windows.GetNamedPipeServerProcessId(windows.Handle(h.Fd()), &pid)
	}
	return pid, err
}

// AcceptProcess rejects all connections other than the exact process started
// by the launcher. Cancellation closes the listener and any pending accept.
func (l *PrivateListener) AcceptProcess(ctx context.Context, expectedPID uint32) (net.Conn, error) {
	if expectedPID == 0 {
		return nil, errors.New("missing expected child PID")
	}
	for {
		type result struct {
			conn net.Conn
			err  error
		}
		ready := make(chan result, 1)
		go func() { c, err := l.Accept(); ready <- result{c, err} }()
		select {
		case <-ctx.Done():
			_ = l.Close()
			r := <-ready
			if r.conn != nil {
				_ = r.conn.Close()
			}
			return nil, ctx.Err()
		case r := <-ready:
			if r.err != nil {
				return nil, r.err
			}
			pid, err := processID(r.conn, true)
			if err != nil || pid != expectedPID {
				_ = r.conn.Close()
				continue
			}
			return r.conn, nil
		}
	}
}

// DialParent checks that the server is the parent identified when the worker
// was launched. The pipe name alone is never treated as authentication.
func DialParent(ctx context.Context, path string, expectedPID uint32) (net.Conn, error) {
	if expectedPID == 0 || expectedPID == uint32(os.Getpid()) {
		return nil, errors.New("invalid parent PID")
	}
	c, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		return nil, err
	}
	pid, err := processID(c, false)
	if err != nil || pid != expectedPID {
		_ = c.Close()
		return nil, errors.New("kernel pipe server identity mismatch")
	}
	return c, nil
}
