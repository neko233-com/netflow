//go:build !windows

package secretstore

func Available() bool                  { return false }
func Protect(string) (string, error)   { return "", ErrUnsupported }
func Unprotect(string) (string, error) { return "", ErrUnsupported }
