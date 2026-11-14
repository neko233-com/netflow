//go:build windows

package agent

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEndpointHasProtectedUserOnlyDACL(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, _, err := createPrivateEndpoint(root, dir, "endpoint-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if !strings.Contains(sddl, "D:P") || !strings.Contains(sddl, user.User.Sid.String()) || strings.Count(sddl, "(A;") != 2 || strings.Contains(sddl, ";;;WD)") {
		t.Fatalf("endpoint ACL is not private: %s", sddl)
	}
	if _, err := f.WriteString("secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(f.Name()); err != nil {
		t.Fatal(err)
	}
}
