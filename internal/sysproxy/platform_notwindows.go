//go:build !windows

package sysproxy

import "errors"

// Unsupported platforms must not report a successful proxy change.
type unsupported struct{}

func (unsupported) Current() (Settings, error) {
	return Settings{}, errors.New("系统代理在此平台尚不支持")
}
func (unsupported) Set(Settings) error { return errors.New("系统代理在此平台尚不支持") }
func platformOther() Controller        { return unsupported{} }
