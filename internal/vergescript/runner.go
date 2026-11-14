// Package vergescript executes Clash Verge's main(config, profileName) scripts
// inside a bounded WebAssembly guest. This is an execution primitive; callers
// must separately obtain consent and validate the resulting configuration.
package vergescript

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/qjsmini"
)

const MaxScriptBytes = 1 << 20
const MaxJSONBytes = 8 << 20
const MaxProfileNameBytes = 4096
const executionTimeout = 5 * time.Second
const maxConcurrent = 2

var slots = make(chan struct{}, maxConcurrent)
var ErrInput = errors.New("invalid script input")
var ErrExecution = errors.New("script execution failed")
var ErrOutput = errors.New("script must return a valid configuration object within the size limit")

// Run evaluates the script in a fresh guest with no mounted host filesystem,
// environment, network or Go functions. Input and output are JSON objects.
// JS exceptions are deliberately redacted because a script can include the
// complete subscription credentials in an exception message.
func Run(ctx context.Context, input []byte, script string, profileName string) (out []byte, err error) {
	if ctx == nil || len(script) == 0 || len(script) > MaxScriptBytes || !utf8.ValidString(script) || strings.ContainsRune(script, '\x00') || len(input) > MaxJSONBytes || !utf8.Valid(input) || len(profileName) > MaxProfileNameBytes || !utf8.ValidString(profileName) || !objectJSON(input) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() {
		if recover() != nil {
			out = nil
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = ErrExecution
			}
		}
	}()
	raw, _ := json.Marshal(string(input))
	name, _ := json.Marshal(profileName)
	source, _ := json.Marshal("\"use strict\";\n" + script + "\n; if (typeof main !== 'function') throw new Error('missing main'); return main;")
	// Source is passed as data to Function, preventing it from breaking out
	// of the host wrapper. Capture JSON builtins before the script executes.
	code := "(function(raw, name, source) { delete globalThis.std; delete globalThis.os; delete globalThis.bjson; delete globalThis.print; delete globalThis.loadScript; delete globalThis.scriptArgs; globalThis.console = {log(){}, info(){}, warn(){}, error(){}, debug(){}}; delete globalThis.setTimeout; delete globalThis.setInterval; delete globalThis.clearTimeout; delete globalThis.clearInterval; const parsed = JSON.parse(raw); const stringify = JSON.stringify; const invoke = Function(source)(); const result = invoke(parsed, name); if (result === null || typeof result !== 'object' || Array.isArray(result) || typeof result.then === 'function') throw new Error('invalid result'); return stringify(result);\n})(" + string(raw) + "," + string(name) + "," + string(source) + ")"
	result, err := qjsmini.Eval(ctx, code, MaxJSONBytes)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, qjsmini.ErrOutput) {
			return nil, ErrOutput
		}
		return nil, ErrExecution
	}
	if len(result) > MaxJSONBytes || !objectJSON(result) {
		return nil, ErrOutput
	}
	return result, nil
}

func objectJSON(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' || !json.Valid(data) {
		return false
	}
	var raw json.RawMessage
	return json.Unmarshal(data, &raw) == nil
}

// RunYAML converts a YAML profile to ordered JSON before invoking Run. The
// returned JSON is also valid YAML and must still be validated by the caller.
func RunYAML(ctx context.Context, yamlData []byte, script, profileName string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	input, err := profile.VergeScriptJSONContext(ctx, yamlData)
	if err != nil {
		return nil, err
	}
	return Run(ctx, input, script, profileName)
}
