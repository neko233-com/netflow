//go:build !windows

package autostart

type unsupported struct{}

func (unsupported) Current() (bool, error) { return false, ErrUnsupported }
func (unsupported) Set(bool) error         { return ErrUnsupported }
func Platform() Controller                 { return unsupported{} }
