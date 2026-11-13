//go:build darwin

package service

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

func install(run CommandRunner) error {
	if run == nil {
		return ErrUnsupported
	}
	src, err := helperSource()
	if err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	if err := os.WriteFile(userTokenPath(), []byte(token), 0o600); err != nil {
		return err
	}
	name, args := AdminCommand(InstallShell(src, token))
	return run(name, args...)
}

func uninstall(run CommandRunner) error {
	if run == nil {
		return ErrUnsupported
	}
	name, args := AdminCommand(UninstallShell())
	if err := run(name, args...); err != nil {
		return err
	}
	_ = os.Remove(userTokenPath())
	return nil
}

func helperSource() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	next := filepath.Join(filepath.Dir(exe), "clash-go-service")
	if _, err := os.Stat(next); err != nil {
		return "", err
	}
	return next, nil
}

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
