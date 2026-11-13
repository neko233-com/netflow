package service

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminCommandAsksForAdministrator(t *testing.T) {
	shell := InstallShell("/tmp/clash-go-service", "tok")
	if !strings.Contains(shell, "launchctl bootstrap system") || !strings.Contains(shell, Label) {
		t.Fatalf("install shell missing launchd bootstrap:\n%s", shell)
	}
	name, args := AdminCommand(shell)
	if name != "osascript" || len(args) != 2 || args[0] != "-e" {
		t.Fatalf("command %s %q", name, args)
	}
	if !strings.Contains(args[1], "with administrator privileges") {
		t.Fatalf("script %s", args[1])
	}
	if !strings.Contains(args[1], "launchctl bootstrap") {
		t.Fatal("admin script dropped the shell")
	}
	off, offArgs := AdminCommand(UninstallShell())
	if !strings.Contains(offArgs[1], "with administrator privileges") || !strings.Contains(offArgs[1], "bootout") {
		t.Fatalf("uninstall %s %q", off, offArgs)
	}
}

func TestPlatformInstallRefusesInCI(t *testing.T) {
	t.Setenv("CI", "true")
	called := false
	m := PlatformWith(func(string, ...string) error {
		called = true
		return nil
	})
	if err := m.Install(); err == nil || !errors.Is(err, ErrCI) || called {
		t.Fatalf("install err %v called %v", err, called)
	}
	if err := m.Uninstall(); err == nil || called {
		t.Fatalf("uninstall err %v called %v", err, called)
	}
	if err := m.StartCore(t.TempDir()); err == nil || called {
		t.Fatalf("start err %v called %v", err, called)
	}
}

type fakeHost struct {
	dirs    []string
	running bool
	err     error
}

func (h *fakeHost) Start(dir string) error {
	if h.err != nil {
		return h.err
	}
	h.dirs = append(h.dirs, dir)
	h.running = true
	return nil
}

func (h *fakeHost) Running() bool { return h.running }

func TestSocketAuthAndStart(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "svc.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeHost{}
	done := make(chan struct{})
	go func() {
		_ = Serve(ln, "secret", host)
		close(done)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	if _, err := Call(socket, "nope", Request{Op: "status"}); err == nil || !strings.Contains(err.Error(), "认证") {
		t.Fatalf("bad token %v", err)
	}
	resp, err := Call(socket, "secret", Request{Op: "status"})
	if err != nil || resp.Running {
		t.Fatalf("status %+v %v", resp, err)
	}
	if _, err := Call(socket, "secret", Request{Op: "start", Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if len(host.dirs) != 1 || host.dirs[0] != dir || !host.Running() {
		t.Fatalf("host %+v", host)
	}
}
