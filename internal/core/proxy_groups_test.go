package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolvedProviderGroupSelectionAndDelay(t *testing.T) {
	dir := t.TempDir()
	config := fmt.Sprintf(`mixed-port: %d
port: 0
socks-port: 0
mode: rule
log-level: error
ipv6: false
dns:
  enable: false
proxy-providers:
  test-provider:
    type: inline
    payload:
      - {name: inline-one, type: direct}
      - {name: inline-two, type: direct}
proxy-groups:
  - name: PROVIDER-TEST
    type: select
    use: [test-provider]
rules:
  - MATCH,DIRECT
`, freePort(t))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	group, err := c.Group("PROVIDER-TEST")
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Nodes) != 2 || group.Nodes[0].Name != "inline-one" || group.Nodes[1].Name != "inline-two" {
		t.Fatalf("provider nodes missing: %+v", group)
	}
	if group.Nodes[0].Provider != "test-provider" || group.Nodes[1].Provider != "test-provider" {
		t.Fatalf("provider identities missing: %+v", group.Nodes)
	}
	providers := c.ProxyProviders()
	if len(providers) != 1 || providers[0].Name != "test-provider" || providers[0].Count != 2 {
		t.Fatalf("providers: %+v", providers)
	}
	if err = c.Select("PROVIDER-TEST", "inline-two"); err != nil {
		t.Fatal(err)
	}
	if selected, err := c.Selected("PROVIDER-TEST"); err != nil || selected != "inline-two" {
		t.Fatalf("selected: %q %v", selected, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	if ms, err := c.TestDelay("PROVIDER-TEST", "inline-one", srv.URL, 3*time.Second); err != nil || ms < 1 {
		t.Fatalf("direct node delay: %d %v", ms, err)
	}
	if _, err := c.TestDelay("PROVIDER-TEST", "inline-one", "file:///secret", time.Second); err == nil {
		t.Fatal("invalid URL accepted")
	}
}
