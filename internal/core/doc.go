// Package core starts and stops the embedded mihomo kernel.
//
// mihomo keeps its listeners, providers and cache in process-wide
// globals. Core serializes Start, Reload and Stop around that singleton.
// Tests that call Start must not use t.Parallel.
package core
