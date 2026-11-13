package app

import (
	"os/exec"
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
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

func writeClipboard(text string) error {
	return mygo.Clipboard.Write(transfer.TextData(text))
}
