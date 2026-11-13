// Package autostart controls starting NetFlow at user login.
package autostart

import "errors"

type Controller interface {
	Current() (bool, error)
	Set(bool) error
}

var ErrUnsupported = errors.New("此平台暂不支持开机自启")
