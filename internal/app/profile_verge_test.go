package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestImportedExtensionsApplyAndInvalidateAgentPreview(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":    "current: p1\nitems:\n  - {uid: p1, type: local, name: Test, file: p1.yaml, option: {proxies: p2, groups: g1, merge: m1}}\n  - {uid: p2, type: proxies, file: p2.yaml}\n  - {uid: g1, type: groups, file: g1.yaml}\n  - {uid: m1, type: merge, file: m1.yaml}\n",
		"profiles/p1.yaml": fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\ndns: {enable: false}\ntun: {enable: false}\nproxies: [{name: old, type: socks5, server: 127.0.0.1, port: 1}]\nproxy-groups: [{name: Select, type: select, proxies: [old, DIRECT]}]\nrules: ['MATCH,DIRECT']\n", port),
		"profiles/p2.yaml": "prepend: [{name: new, type: socks5, server: 127.0.0.1, port: 2}]\nappend: []\ndelete: [old]\n",
		"profiles/g1.yaml": "prepend: []\nappend: [{name: Extra, type: select, proxies: [DIRECT]}]\ndelete: []\n",
		"profiles/m1.yaml": "profile: {store-selected: true}\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parsed, err := migration.ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := parsed.ImportVerge(dir); err != nil {
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
	effective, err := a.core.EffectiveConfig()
	if err != nil || !strings.Contains(string(effective), "name: new") || !strings.Contains(string(effective), "name: Extra") || strings.Contains(string(effective), "name: old") {
		t.Fatalf("extensions not active: %s %v", effective, err)
	}
	groups, err := a.agentGroups()
	if err != nil || len(groups.Groups) != 2 || groups.Groups[0].Name != "Select" || groups.Groups[1].Name != "Extra" {
		t.Fatalf("agent did not expose effective groups: %+v %v", groups, err)
	}
	proposal, err := a.agentPreview(agent.Change{Scope: "global", Operation: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := a.profiles.Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal("imported profile missing")
	}
	archive := filepath.Join(dir, catalog.Items[0].Option.VergeArchive)
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("changed"))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("could not change archive")
	}
	if _, err := a.agentApply(proposal.ProposalID); err == nil {
		t.Fatal("agent accepted a preview after the extension archive changed")
	}
}
