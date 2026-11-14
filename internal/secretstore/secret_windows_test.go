//go:build windows

package secretstore

import (
	"strings"
	"testing"
)

func TestCurrentUserCredentialProtection(t *testing.T) {
	const secret = "synthetic-password-例子"
	protected, err := Protect(secret)
	if err != nil || strings.Contains(protected, secret) {
		t.Fatalf("protect failed: %v", err)
	}
	got, err := Unprotect(protected)
	if err != nil || got != secret {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := Unprotect("dpapi:v1:not-base64!"); err == nil {
		t.Fatal("invalid credential accepted")
	}
}
