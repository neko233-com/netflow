//go:build windows

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The protected DACL is set in the initial create, relative to a pinned
// directory handle; no bearer token is written through a replaceable path.
func createPrivateEndpoint(root *os.Root, displayDir, prefix string) (*os.File, string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, "", err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, "", err
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()
	for i := 0; i < 10; i++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(nonce[:]) + ".json"
		objectName, err := windows.NewNTUnicodeString(name)
		if err != nil {
			return nil, "", err
		}
		oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(dir.Fd()), ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
		oa.Length = uint32(unsafe.Sizeof(oa))
		var iosb windows.IO_STATUS_BLOCK
		var handle windows.Handle
		err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.SYNCHRONIZE, &oa, &iosb, nil,
			windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, windows.FILE_CREATE,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(handle), filepath.Join(displayDir, name)), name, nil
	}
	return nil, "", errors.New("could not allocate private endpoint file")
}
