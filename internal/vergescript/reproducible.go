package vergescript

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

var ErrNonDeterministic = errors.New("script output changed between identical executions")

// ReproducibleResult binds exactly the inputs and output used by a preview.
// It does not assert that the output is a valid or safe core configuration.
type ReproducibleResult struct {
	Body              []byte
	InputSHA256       [32]byte
	ScriptSHA256      [32]byte
	ProfileNameSHA256 [32]byte
	OutputSHA256      [32]byte
	Clock             time.Time
}
type executeAt func(context.Context, []byte, string, string, time.Time) ([]byte, error)

// CheckYAMLAt runs the same script twice with a fixed approval clock. Callers
// must additionally validate core configuration and reject stale inputs.
func CheckYAMLAt(ctx context.Context, yamlData []byte, script, profileName string, clock time.Time) (ReproducibleResult, error) {
	if ctx == nil || clock.IsZero() {
		return ReproducibleResult{}, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 2*executionTimeout)
	defer cancel()
	input, err := profile.VergeScriptJSONContext(ctx, yamlData)
	if err != nil {
		return ReproducibleResult{}, err
	}
	return checkAt(ctx, input, script, profileName, clock, RunAt)
}
func checkAt(ctx context.Context, input []byte, script, name string, clock time.Time, run executeAt) (ReproducibleResult, error) {
	if ctx == nil || run == nil || clock.IsZero() {
		return ReproducibleResult{}, ErrInput
	}
	fixed := clock.UTC()
	first, err := run(ctx, input, script, name, fixed)
	if err != nil {
		return ReproducibleResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReproducibleResult{}, err
	}
	second, err := run(ctx, input, script, name, fixed)
	if err != nil {
		return ReproducibleResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReproducibleResult{}, err
	}
	if !bytes.Equal(first, second) {
		return ReproducibleResult{}, ErrNonDeterministic
	}
	return ReproducibleResult{Body: append([]byte(nil), first...), InputSHA256: sha256.Sum256(input), ScriptSHA256: sha256.Sum256([]byte(script)), ProfileNameSHA256: sha256.Sum256([]byte(name)), OutputSHA256: sha256.Sum256(first), Clock: fixed}, nil
}
