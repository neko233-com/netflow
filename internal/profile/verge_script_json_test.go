package profile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVergeScriptJSONKeepsOrderAndMaterializesMerges(t *testing.T) {
	source := []byte("base: &base\n  first: alpha\n  second: beta\ndns:\n  nameserver-policy:\n    +.alpha.example: 1.1.1.1\n    +.beta.example: 8.8.8.8\nitem:\n  <<: *base\n  second: override\n  active: true\n")
	got, err := VergeScriptJSON(source)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"base":{"first":"alpha","second":"beta"},"dns":{"nameserver-policy":{"+.alpha.example":"1.1.1.1","+.beta.example":"8.8.8.8"}},"item":{"first":"alpha","second":"override","active":true}}`
	if string(got) != want {
		t.Fatalf("wrong ordered JSON: %s", got)
	}
}
func TestVergeScriptJSONRejectsAmbiguousDocuments(t *testing.T) {
	for _, input := range []string{"a: 1\na: 2\n", "a: .nan\n", "a: !custom value\n", "a: 1\n---\nb: 2\n", "- list\n"} {
		if _, err := VergeScriptJSON([]byte(input)); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	if _, err := VergeScriptJSON([]byte("a: " + strings.Repeat("x", maxVergeScriptJSON))); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestVergeScriptJSONContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VergeScriptJSONContext(ctx, []byte("a: 1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled conversion: %v", err)
	}
}

type cancelDuringConversion struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelDuringConversion) Err() error {
	c.checks++
	if c.checks == 100 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestVergeScriptJSONCancelsDuringAliasExpansion(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelDuringConversion{Context: base, cancel: cancel}
	var doc strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&doc, "key%d: value\n", i)
	}
	if _, err := VergeScriptJSONContext(ctx, []byte(doc.String())); !errors.Is(err, context.Canceled) {
		t.Fatalf("conversion ignored cancellation: %v", err)
	}
	if ctx.checks < 100 {
		t.Fatal("conversion did not reach the cancellation point")
	}
}
