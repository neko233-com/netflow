package vergescript

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestCheckYAMLAtBindsPreviewInputsAndOutput(t *testing.T) {
	clock := time.Date(2026, 11, 15, 3, 4, 5, 0, time.UTC)
	script := `function main(c,n){c.rule=n;c.time=Date.now();c.random=Math.random();return c}`
	first, err := CheckYAMLAt(context.Background(), []byte("rules: [MATCH,DIRECT]\n"), script, "profile", clock)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CheckYAMLAt(context.Background(), []byte("rules: [MATCH,DIRECT]\n"), script, "profile", clock)
	if err != nil {
		t.Fatal(err)
	}
	if first.OutputSHA256 != again.OutputSHA256 || first.OutputSHA256 != sha256.Sum256(first.Body) || first.ScriptSHA256 != sha256.Sum256([]byte(script)) || first.ProfileNameSHA256 != sha256.Sum256([]byte("profile")) || !first.Clock.Equal(clock) {
		t.Fatal("preview identity is inconsistent")
	}
	first.Body[0] = 'x'
	if first.OutputSHA256 != again.OutputSHA256 || again.Body[0] != '{' {
		t.Fatal("result buffers were shared")
	}
}
func TestCheckAtRejectsDifferentOutputAndCancellation(t *testing.T) {
	n := 0
	fake := func(context.Context, []byte, string, string, time.Time) ([]byte, error) {
		n++
		if n == 1 {
			return []byte(`{"v":1}`), nil
		}
		return []byte(`{"v":2}`), nil
	}
	if _, err := checkAt(context.Background(), []byte(`{}`), "x", "p", time.Now(), fake); !errors.Is(err, ErrNonDeterministic) {
		t.Fatalf("unstable result accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CheckYAMLAt(ctx, []byte("a: 1"), `function main(c){return c}`, "p", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := CheckYAMLAt(context.Background(), []byte("a: 1"), `function main(c){return c}`, "p", time.Time{}); !errors.Is(err, ErrInput) {
		t.Fatalf("missing clock accepted: %v", err)
	}
}
