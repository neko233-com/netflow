package ui

import "testing"

func TestSafeProfileHome(t *testing.T) {
	for raw, want := range map[string]bool{"https://example.test/account": true, "http://localhost:8080/": true, "javascript:alert(1)": false, "file:///tmp/example": false, "https://": false} {
		if got := safeProfileHome(raw); got != want {
			t.Errorf("%q = %v", raw, got)
		}
	}
}
