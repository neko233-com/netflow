# QuickJS WebAssembly runtime provenance

The embedded `qjs.wasm` originates from `github.com/fastschema/qjs` v0.0.6 (Go module checksum `h1:C45KMmQMd21UwsUAmQHxUxiWOfzwTg1GJW0DA0AbFEE=`). The WASM SHA-256 is `88fcbbead33cca3ec8394feb0fb3eec8047ec9ac5062aba7a63799cee11989b7`. Upstream identifies its QuickJS-NG submodule at commit `d01ca4491fb24ccfeccb4c7394e28a3b21fd5986`.

The local minimal ABI adapter uses the existing metacubex wazero dependency, caps WASM linear memory at 128 MiB, enables context cancellation, grants no host filesystem mounts or Go proxy callbacks, uses a caller-fixed wall clock and deterministic guest random source, uses only the bundled WASM, and closes each runtime after execution. These are resource and capability restrictions, not proof against every possible runtime vulnerability. The runtime is not wired to subscription activation until explicit approval, preview, validation, and stale-input handling are implemented.

The upstream and QuickJS-NG licenses are shipped in `LICENSES/third_party/fastschema-qjs`.
