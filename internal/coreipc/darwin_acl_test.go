package coreipc

import "testing"

func TestDarwinACLAbsent(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"ordinary", "drwxr-xr-x 5 0 0 160 Nov 14 00:00 /private/var/db\n", true},
		{"xattr", "drwx------@ 5 0 0 160 Nov 14 00:00 /private/var/db\n", true},
		{"acl indicator", "drwx------+ 5 0 0 160 Nov 14 00:00 /private/var/db\n", false},
		{"acl hidden by xattr indicator", "drwx------@ 5 0 0 160 Nov 14 00:00 /private/var/db\n 0: group:everyone allow write\n", false},
		{"empty", "", false},
		{"non-directory", "-rw------- 1 0 0 160 Nov 14 00:00 /private/var/db\n", false},
		{"truncated", "drwx------ 5 0\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := darwinACLAbsent([]byte(tc.output)); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
