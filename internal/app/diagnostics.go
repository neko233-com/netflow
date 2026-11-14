package app

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/neko233-com/netflow"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
)

// diagnostics is intentionally an allowlist rather than a redaction pass:
// no user-controlled configuration, error text, paths, or connections leave it.
func (a *App) diagnostics() agent.Diagnostics {
	out := agent.Diagnostics{SchemaVersion: 1, AppVersion: netflow.Version(), CoreVersion: core.Version(), OS: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version(), Mode: "unknown"}
	if a == nil {
		return out
	}
	out.Headless = a.headless
	out.TUNPending, out.TUNHasError, out.PrivilegedKernel = a.tunBusy, a.tunLastError != "", a.privilegedTUN
	if !a.started.IsZero() {
		if uptime := time.Since(a.started); uptime > 0 {
			out.UptimeSeconds = int64(uptime.Seconds())
		}
	}
	if a.rewrites != nil {
		out.RewriteRevision = a.rewrites.Snapshot().Revision
	}
	if a.profiles != nil {
		if catalog, err := a.profiles.Load(); err == nil {
			out.ProfileCatalogReadable = true
			out.ProfileCount = len(catalog.Items)
		}
	}
	if a.core != nil {
		status := a.core.Status()
		out.CoreRunning, out.CoreHasError, out.TUN = status.Running, status.Error != "", status.TUN
		switch status.Mode {
		case "rule", "global", "direct":
			out.Mode = status.Mode
		}
		if status.Running {
			connections, _, _ := a.core.Connections()
			out.ConnectionCount = len(connections)
		}
	}
	return out
}

func (a *App) diagnosticsText() (string, error) {
	data, err := json.MarshalIndent(a.diagnostics(), "", "  ")
	return string(data), err
}
