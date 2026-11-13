//go:build !darwin

package service

func install(CommandRunner) error { return ErrUnsupported }

func uninstall(CommandRunner) error { return ErrUnsupported }
