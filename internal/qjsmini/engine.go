// Package qjsmini runs a single string-valued QuickJS expression in an
// isolated WASM module. Only the small ABI needed by Verge scripts is exposed.
package qjsmini

import (
	"context"
	_ "embed"
	"errors"
	"io"

	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/api"
	wsp1 "github.com/metacubex/wazero/imports/wasi_snapshot_preview1"
)

//go:embed qjs.wasm
var wasmBytes []byte

var compilationCache = wazero.NewCompilationCache()
var ErrExecution = errors.New("guest execution failed")
var ErrOutput = errors.New("guest output is invalid or too large")

// Eval uses a fresh guest with a 128 MiB linear memory ceiling, no host
// filesystem or environment and no Go callbacks. The caller supplies a
// deadline, an output limit and its own concurrency limit.
func Eval(ctx context.Context, code string, outputLimit int) ([]byte, error) {
	return eval(ctx, code, 64<<20, outputLimit)
}
func eval(ctx context.Context, code string, heapLimit uint64, outputLimit int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || outputLimit < 1 {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrExecution
	}
	cfg := wazero.NewRuntimeConfig().WithCompilationCache(compilationCache).WithMemoryLimitPages(2048).WithCloseOnContextDone(true)
	guest := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer guest.Close(context.Background())
	fail := func() (out []byte, err error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrExecution
	}
	compiled, err := guest.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fail()
	}
	if _, err = wsp1.Instantiate(ctx, guest); err != nil {
		return fail()
	}
	denyProxy := func(context.Context, api.Module, uint32, uint64, uint32, uint32) uint64 { return 0 }
	if _, err = guest.NewHostModuleBuilder("env").NewFunctionBuilder().WithFunc(denyProxy).Export("jsFunctionProxy").Instantiate(ctx); err != nil {
		return fail()
	}
	mod, err := guest.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithStartFunctions("").WithSysWalltime().WithSysNanotime().WithFSConfig(wazero.NewFSConfig()).WithStdout(io.Discard).WithStderr(io.Discard))
	if err != nil {
		return fail()
	}
	call := func(name string, args ...uint64) (uint64, error) {
		fn := mod.ExportedFunction(name)
		if fn == nil {
			return 0, ErrExecution
		}
		result, e := fn.Call(ctx, args...)
		if e != nil || len(result) != 1 {
			return 0, ErrExecution
		}
		return result[0], nil
	}
	runtimePtr, err := call("New_QJS", heapLimit, 512<<10, 0, 0)
	if err != nil || runtimePtr == 0 {
		return fail()
	}
	scriptContext, err := call("QJS_GetContext", runtimePtr)
	if err != nil || scriptContext == 0 {
		return fail()
	}
	alloc := func(text string) (uint64, error) {
		p, e := call("malloc", uint64(len(text)+1))
		if e != nil || p == 0 {
			return 0, ErrExecution
		}
		data := append([]byte(text), 0)
		if !mod.Memory().Write(uint32(p), data) {
			return 0, ErrExecution
		}
		return p, nil
	}
	source, err := alloc(code)
	if err != nil {
		return fail()
	}
	file, err := alloc("profile.js")
	if err != nil {
		return fail()
	}
	option, err := call("QJS_CreateEvalOption", source, 0, 0, file, 1<<3)
	if err != nil || option == 0 {
		return fail()
	}
	value, err := call("QJS_Eval", scriptContext, option)
	if err != nil {
		return fail()
	}
	exception, err := call("JS_HasException", scriptContext)
	if err != nil || exception != 0 {
		return fail()
	}
	isString, err := call("QJS_IsString", value)
	if err != nil || isString == 0 {
		return nil, ErrOutput
	}
	packedPtr, err := call("QJS_ToCString", scriptContext, value)
	if err != nil || packedPtr == 0 {
		return fail()
	}
	packed, ok := mod.Memory().ReadUint64Le(uint32(packedPtr))
	if !ok {
		return fail()
	}
	address, size := uint32(packed>>32), uint32(packed)
	if uint64(size) > uint64(outputLimit) {
		return nil, ErrOutput
	}
	data, ok := mod.Memory().Read(address, size)
	if !ok {
		return fail()
	}
	out := append([]byte(nil), data...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
