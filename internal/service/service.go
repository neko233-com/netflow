// Package service is the privileged helper Verge calls service mode.
// The helper is a launchd daemon. The app talks to it over a unix socket.
// Tests use Memory. Platform refuses to install when CI is set.
package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const (
	// Label is the launchd job name.
	Label = "app.clashgo.desktop.service"
	// SocketPath is the unix socket the daemon listens on.
	SocketPath = "/var/run/app.clashgo.desktop.service.sock"
	// HelperPath is where the installed binary lives.
	HelperPath = "/Library/PrivilegedHelperTools/app.clashgo.desktop.service"
	// PlistPath is the launch daemon definition.
	PlistPath = "/Library/LaunchDaemons/app.clashgo.desktop.service.plist"
	// TokenPath is the root-owned copy of the IPC secret.
	TokenPath = "/Library/PrivilegedHelperTools/app.clashgo.desktop.service.token"
)

// ErrCI is returned when an install is attempted in CI.
var ErrCI = errors.New("CI 中不会安装服务")

// ErrUnsupported is returned on systems without a launchd helper.
var ErrUnsupported = errors.New("NetFlow 服务模式尚未实现")

// ErrAuth is returned when the socket token does not match.
var ErrAuth = errors.New("服务认证失败")

// Status is the helper as the settings row shows it.
type Status struct {
	Installed bool
	Running   bool
}

// Manager installs the helper and asks it to run the core.
type Manager interface {
	Status() (Status, error)
	Install() error
	Uninstall() error
	StartCore(dir string) error
}

// Memory is a test double. It never installs a daemon or starts mihomo.
type Memory struct {
	Installed  bool
	Starts     int
	Dir        string
	InstallErr error
	StartErr   error
}

// Status reports the in-memory flag.
func (m *Memory) Status() (Status, error) {
	if m == nil {
		return Status{}, nil
	}
	return Status{Installed: m.Installed, Running: m.Installed}, nil
}

// Install marks the helper installed.
func (m *Memory) Install() error {
	if m == nil {
		return errors.New("nil service")
	}
	if m.InstallErr != nil {
		return m.InstallErr
	}
	m.Installed = true
	return nil
}

// Uninstall clears the flag.
func (m *Memory) Uninstall() error {
	if m == nil {
		return nil
	}
	m.Installed = false
	return nil
}

// StartCore records the config directory. It does not start mihomo.
func (m *Memory) StartCore(dir string) error {
	if m == nil {
		return errors.New("nil service")
	}
	if m.StartErr != nil {
		return m.StartErr
	}
	m.Starts++
	m.Dir = dir
	return nil
}

// Blocked reports whether this process must not install or contact a helper.
func Blocked() bool {
	return os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
}

// Request is one IPC line after the auth token.
type Request struct {
	Op  string `json:"op"`
	Dir string `json:"dir,omitempty"`
}

// Response is one IPC line.
type Response struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Running bool   `json:"running,omitempty"`
}

// Host is what the daemon does after a command. Tests pass a fake.
// The real helper starts the embedded core.
type Host interface {
	Start(dir string) error
	Running() bool
}

// Serve accepts connections until the listener closes.
// The first line of each connection must be the token.
func Serve(ln net.Listener, token string, host Host) error {
	if ln == nil {
		return errors.New("nil listener")
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		handleConn(conn, token, host)
	}
}

func handleConn(conn net.Conn, token string, host Host) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	if strings.TrimSpace(line) != token || token == "" {
		// The client writes the request in the same burst. Read it before
		// closing so the write is not a broken pipe.
		_, _ = r.ReadString('\n')
		writeResp(conn, Response{OK: false, Error: ErrAuth.Error()})
		return
	}
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return
		}
		var req Request
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &req); err != nil {
			writeResp(conn, Response{OK: false, Error: err.Error()})
			continue
		}
		writeResp(conn, dispatch(req, host))
	}
}

func dispatch(req Request, host Host) Response {
	switch req.Op {
	case "status":
		running := host != nil && host.Running()
		return Response{OK: true, Running: running}
	case "start":
		if host == nil {
			return Response{OK: false, Error: "no host"}
		}
		if err := host.Start(req.Dir); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Running: true}
	default:
		return Response{OK: false, Error: "unknown op"}
	}
}

func writeResp(w io.Writer, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = w.Write(b)
}

// Call dials socket, sends token, then one request.
func Call(socket, token string, req Request) (Response, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n", token)
	buf.Write(b)
	buf.WriteByte('\n')
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "service error"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
