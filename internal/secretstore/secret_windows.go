//go:build windows

package secretstore

import (
	"encoding/base64"
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const prefix = "dpapi:v1:"

func Available() bool { return true }

// Protect binds the ciphertext to the current Windows user. UI prompts and
// machine-wide protection are deliberately disabled.
func Protect(secret string) (string, error) {
	if len(secret) == 0 || len(secret) > maxSecretBytes {
		return "", errors.New("credential length is invalid")
	}
	input := []byte(secret)
	defer clear(input)
	data := windows.DataBlob{Size: uint32(len(input)), Data: &input[0]}
	var output windows.DataBlob
	err := windows.CryptProtectData(&data, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(input)
	if err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Data == nil || output.Size == 0 || output.Size > 2*maxSecretBytes {
		return "", errors.New("credential protection returned invalid data")
	}
	return prefix + base64.StdEncoding.EncodeToString(unsafe.Slice(output.Data, output.Size)), nil
}

func Unprotect(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, prefix) || len(encoded) > 4*maxSecretBytes {
		return "", errors.New("protected credential format is invalid")
	}
	input, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, prefix))
	if err != nil || len(input) == 0 || len(input) > 2*maxSecretBytes {
		return "", errors.New("protected credential format is invalid")
	}
	data := windows.DataBlob{Size: uint32(len(input)), Data: &input[0]}
	var output windows.DataBlob
	err = windows.CryptUnprotectData(&data, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(input)
	if err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Data == nil || output.Size == 0 || output.Size > maxSecretBytes {
		return "", errors.New("protected credential is invalid")
	}
	plain := unsafe.Slice(output.Data, output.Size)
	result := string(plain)
	clear(plain)
	return result, nil
}
