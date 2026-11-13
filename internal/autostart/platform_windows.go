//go:build windows

package autostart

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const valueName = "NetFlow"

type windowsController struct {
	key     string
	command func() (string, error)
}

func Platform() Controller {
	return &windowsController{key: runKey, command: func() (string, error) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		return syscall.EscapeArg(exe), nil
	}}
}

func (c *windowsController) Current() (bool, error) {
	command, err := c.command()
	if err != nil {
		return false, err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, c.key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer k.Close()
	value, _, err := k.GetStringValue(valueName)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value == command, nil
}

func (c *windowsController) Set(enabled bool) error {
	command, err := c.command()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, c.key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	value, _, err := k.GetStringValue(valueName)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	if err == nil && value != command {
		return errors.New("自启项已由其他 NetFlow 程序设置，未覆盖")
	}
	if enabled {
		return k.SetStringValue(valueName, command)
	}
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return k.DeleteValue(valueName)
}
