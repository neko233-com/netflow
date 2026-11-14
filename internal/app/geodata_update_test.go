package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/geoupdate"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestFailedGeoApplicationIsReportedAndQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mixed-port: 0\nport: 0\nsocks-port: 0\ndns: {enable: false}\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, geoupdate.PendingDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, geoupdate.PendingDirectory, "manifest.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	status, err := a.agentStatus()
	if err != nil || status.GeoError == "" || status.GeoRestart {
		t.Fatalf("missing GeoData failure status: %+v %v", status, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), geoupdate.RejectedPrefix) {
			found = true
		}
	}
	if !found {
		t.Fatal("failed transaction was not quarantined")
	}
}
