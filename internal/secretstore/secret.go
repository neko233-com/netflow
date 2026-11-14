// Package secretstore protects small legacy credentials using the current
// operating-system account. It never falls back to storing new plaintext.
package secretstore

import "errors"

var ErrUnsupported = errors.New("account-bound credential protection is unavailable on this platform")

const maxSecretBytes = 64 << 10
