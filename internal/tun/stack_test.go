package tun

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestMipsStackIsAccepted checks the Verge default "mips" against mihomo v1.19.33.
// UnmarshalText lowercases the token, and "mips" is TunMips (display name "Mips").
func TestMipsStackIsAccepted(t *testing.T) {
	var stack C.TUNStack
	if err := stack.UnmarshalText([]byte(DefaultStack)); err != nil {
		t.Fatal(err)
	}
	if stack != C.TunMips || stack.String() != "Mips" {
		t.Fatalf("stack %d %q", stack, stack.String())
	}
	if StackLabel(DefaultStack) != "Mips" {
		t.Fatalf("label %q", StackLabel(DefaultStack))
	}
}
