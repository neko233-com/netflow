package app

import (
	"os/exec"
	"runtime"
	"strings"
)

func openPath(path string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{path}
	case "windows":
		name, args = "explorer", []string{path}
	default:
		name, args = "xdg-open", []string{path}
	}
	return exec.Command(name, args...).Start()
}

func writeClipboard(text string) {
	if runtime.GOOS != "darwin" {
		return
	}
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}
