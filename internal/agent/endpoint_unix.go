//go:build !windows

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
)

func createPrivateEndpoint(root *os.Root, _ string, prefix string) (*os.File, string, error) {
	for i := 0; i < 10; i++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(nonce[:]) + ".json"
		f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return f, name, nil
	}
	return nil, "", errors.New("could not allocate private endpoint file")
}
