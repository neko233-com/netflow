package core

import "testing"

func TestVerifyTUNStateReportsFailedStartAndStop(t *testing.T) {
	if verifyTUNState(false, false) != nil || verifyTUNState(true, true) != nil {
		t.Fatal("matching state rejected")
	}
	if verifyTUNState(true, false) == nil || verifyTUNState(false, true) == nil {
		t.Fatal("mismatched TUN state accepted")
	}
}
