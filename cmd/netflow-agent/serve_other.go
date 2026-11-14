//go:build !windows

package main

import "os/exec"

func configureHeadlessProcess(*exec.Cmd) {}
