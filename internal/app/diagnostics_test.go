package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/profile"
)

type diagnosticsTestEngine struct{ coreEngine }

func (diagnosticsTestEngine) Status() core.Status {
	return core.Status{Running: true, TUN: false, Mode: "private-mode-secret", Error: "private-error-secret", ConfigDir: "private-path-secret"}
}
func (diagnosticsTestEngine) Connections() ([]conn.Item, int64, int64) {
	return []conn.Item{{ID: "private-connection-secret", Host: "private-host-secret"}}, 0, 0
}

func TestDiagnosticsExcludesUserData(t *testing.T) {
	dir := t.TempDir()
	store := profile.NewStore(dir)
	if err := store.Save(profile.File{Items: []profile.CatalogItem{{UID: "private-id-secret", Name: "private-name-secret", URL: "https://private-url-secret/credential"}}}); err != nil {
		t.Fatal(err)
	}
	a := &App{core: diagnosticsTestEngine{}, profiles: store, tunLastError: "private-tun-error-secret", started: time.Now().Add(-2 * time.Second)}
	result := a.diagnostics()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") || result.Mode != "unknown" || !result.CoreRunning || !result.CoreHasError || !result.TUNHasError || !result.ProfileCatalogReadable || result.ProfileCount != 1 || result.ConnectionCount != 1 || result.UptimeSeconds < 1 {
		t.Fatalf("unexpected or sensitive diagnostics: %s", data)
	}
}
