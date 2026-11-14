package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestProviderNodesAppearInApplicationModel(t *testing.T) {
	var err error
	dir := t.TempDir()
	port := freePort(t)
	config := fmt.Sprintf(`mixed-port: %d
port: 0
socks-port: 0
mode: rule
log-level: error
ipv6: false
dns:
  enable: false
proxy-providers:
  inline-provider:
    type: inline
    payload:
      - {name: p-node-one, type: direct}
      - {name: p-node-two, type: direct}
proxy-groups:
  - name: CUSTOM-PROVIDER-GROUP
    type: select
    use: [inline-provider]
rules:
  - MATCH,DIRECT
`, port)
	if err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err = a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core failed: %s", a.Home().Error)
	}
	if len(a.model.Groups) != 1 || len(a.model.Groups[0].Nodes) != 2 || a.model.Groups[0].Nodes[1].Name != "p-node-two" {
		t.Fatalf("model groups: %+v", a.model.Groups)
	}
	if len(a.model.Providers) != 1 || a.model.Providers[0].Name != "inline-provider" || a.model.Providers[0].Count != 2 {
		t.Fatalf("model providers: %+v", a.model.Providers)
	}
	if err = a.SelectProxy("CUSTOM-PROVIDER-GROUP", "p-node-two"); err != nil {
		t.Fatal(err)
	}
	if a.model.Groups[0].Now != "p-node-two" {
		t.Fatalf("model selection: %+v", a.model.Groups[0])
	}
	if err = a.SetMode("global"); err != nil {
		t.Fatal(err)
	}
	if len(a.model.Groups) < 2 || a.model.Groups[0].Name != "GLOBAL" || len(a.model.Groups[0].Nodes) == 0 {
		t.Fatalf("global selector missing: %+v", a.model.Groups)
	}
	if a.model.Home.Node.Group != "GLOBAL" {
		t.Fatalf("home is not showing global selection: %+v", a.model.Home.Node)
	}
}
