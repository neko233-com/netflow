package ruleexpiry

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMetadataRoundTripAndUntrustedNestedHeader(t *testing.T) {
	base := []byte(prefix + "[1]\nrules: ['MATCH,DIRECT']\n")
	deadline := time.Now().UTC().Add(time.Minute).Truncate(time.Nanosecond)
	encoded, err := Encode(base, []time.Time{deadline})
	if err != nil {
		t.Fatal(err)
	}
	decoded, deadlines, err := Decode(encoded)
	if err != nil || !bytes.Equal(decoded, base) || len(deadlines) != 1 || !deadlines[0].Equal(deadline) {
		t.Fatalf("round trip: %v %+v", err, deadlines)
	}
	encoded, err = Encode(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, deadlines, err = Decode(encoded)
	if err != nil || !bytes.Equal(decoded, base) || len(deadlines) != 0 {
		t.Fatal("untrusted nested header was interpreted")
	}
}

func TestInvalidMetadataRejected(t *testing.T) {
	for _, value := range []string{prefix + "[0]\nrules: []", prefix + "[bad]\nrules: []", prefix + strings.Repeat("1", 33<<10) + "\n"} {
		if _, _, err := Decode([]byte(value)); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	if _, err := Encode(nil, make([]time.Time, 1001)); err == nil {
		t.Fatal("too many deadlines accepted")
	}
}
