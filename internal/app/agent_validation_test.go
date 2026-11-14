package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestAgentPreviewChecksProvidersAndDoesNotRepairGeoData(t *testing.T) {
	port := freePort(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "nodes.yaml")
	if err := os.WriteFile(file, []byte("proxies: [{name: node, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nproxy-providers:\n  nodes: {type: file, path: nodes.yaml, health-check: {enable: false}}\nproxy-groups: [{name: Select, type: select, use: [nodes]}]\nrules: ['MATCH,DIRECT']\n", port)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if !a.core.Status().Running {
		t.Fatalf("core failed: %s", a.model.Home.Error)
	}
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,example.test,DIRECT"}}}
	draft, err := a.prepareAgentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := validateConfigurations(context.Background(), dir, draft.configs)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.verifyDraftSources(draft, checked); err != nil {
		t.Fatal(err)
	}
	a.tunBusy = true
	if _, err := a.finishAgentPreview(draft, checked); err == nil {
		t.Fatal("network transition during validation was ignored")
	}
	a.tunBusy = false
	proposal, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("wrong: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("changed provider did not invalidate preview")
	}
	if _, err := a.agentPreview(change); err == nil || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("invalid provider accepted: %v", err)
	}
	if err := os.WriteFile(file, []byte("proxies: [{name: node, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("not a database"))
	}))
	defer srv.Close()
	remote := strings.Replace(base, "proxy-providers:\n", "proxy-providers:\n  remote: {type: http, url: '"+srv.URL+"', interval: 86400}\n", 1)
	if err := os.WriteFile(path, []byte(remote), 0600); err != nil {
		t.Fatal(err)
	}
	preview, err := a.agentPreview(change)
	if err != nil || len(preview.Warnings) == 0 || !strings.Contains(strings.Join(preview.Warnings, " "), "HTTP provider caches are missing") {
		t.Fatalf("missing cache warning: %+v %v", preview.Warnings, err)
	}
	if requests.Load() != 0 {
		t.Fatal("preview downloaded an HTTP provider")
	}
	geo := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(geo, []byte("invalid database"), 0600); err != nil {
		t.Fatal(err)
	}
	geoConfig := strings.Replace(base, "rules: ['MATCH,DIRECT']", "geox-url: {mmdb: '"+srv.URL+"'}\nrules: ['GEOIP,CN,DIRECT', 'MATCH,DIRECT']", 1)
	if err := os.WriteFile(path, []byte(geoConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentPreview(change); err == nil {
		t.Fatal("invalid geodata accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("preview downloaded geodata")
	}
	data, err := os.ReadFile(geo)
	if err != nil || string(data) != "invalid database" {
		t.Fatalf("preview modified geodata: %q %v", data, err)
	}
}
