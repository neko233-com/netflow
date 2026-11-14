package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestImportedExtensionsApplyAndInvalidateAgentPreview(t *testing.T) {
	port := freePort(t)
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
	catalogSnapshot, catalogHash, err := a.profiles.LoadSnapshot()
	if err != nil || len(catalogSnapshot.Items) != 1 {
		t.Fatal("imported catalog snapshot missing")
	}
	changed := catalogSnapshot
	changed.Items = append(changed.Items[:0:0], catalogSnapshot.Items...)
	changed.Items[0].Option.VergeExtensions = false
	if err := a.profiles.Save(changed); err != nil {
		t.Fatal(err)
	}
	before := a.rewrites.Snapshot()
	after := before
	after.Global = rewrite.Layer{Prepend: []string{"DOMAIN,extension.test,Extra"}}
	options := a.kernelOptions.Snapshot()
	_, rules, hashes, err := a.previewSources(catalogSnapshot, catalogHash, &options, before, after, a.core.ProfileID(), true, nil, nil)
	if err != nil || len(rules) == 0 || rules[0] != "DOMAIN,extension.test,Extra" || hashes[filepath.Join(dir, "profiles.json")] != catalogHash {
		t.Fatalf("preview did not use the captured catalog: %v %v", rules, err)
	}
	if err := a.profiles.Save(catalogSnapshot); err != nil {
		t.Fatal(err)
	}
	change := agent.Change{Scope: "global", Operation: "set", Layer: after.Global}
	withGroup, err := a.agentPreview(change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(withGroup.ProposalID); err != nil {
		t.Fatal(err)
	}
	if err := a.SetKernelOption("ipv6", false); err != nil {
		t.Fatalf("kernel option validation omitted imported extension: %v", err)
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
