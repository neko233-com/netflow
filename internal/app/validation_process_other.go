//go:build !windows

package app

import "os/exec"

func configureValidationProcess(*exec.Cmd) {}
