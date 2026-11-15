package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/ruleexpiry"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
	"go.yaml.in/yaml/v3"
)

func TestKernelCompositionBindsExpiryToExactLeadingRules(t *testing.T) {
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['DOMAIN,duplicate.test,DIRECT', 'MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	profileID := a.core.ProfileID()
	now := time.Now().UTC()
	first, second := now.Add(time.Minute), now.Add(2*time.Minute)
	state := a.rewrites.Snapshot()
	state.Connections = []rewrite.Connection{
		{ID: "first", ProfileID: profileID, Rule: "DOMAIN,duplicate.test,DIRECT", ExpiresAt: first},
		{ID: "expired", ProfileID: profileID, Rule: "DOMAIN,expired.test,REJECT", ExpiresAt: now.Add(-time.Minute)},
		{ID: "other", ProfileID: "other", Rule: "DOMAIN,other.test,REJECT", ExpiresAt: second},
		{ID: "second", ProfileID: profileID, Rule: "DOMAIN,second.test,REJECT", ExpiresAt: second},
	}
	if _, err := a.rewrites.Replace(state, state.Revision); err != nil {
		t.Fatal(err)
	}
	encoded, err := a.composeRuntimeForKernel(base, profileID)
	if err != nil {
		t.Fatal(err)
	}
	data, deadlines, err := ruleexpiry.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 2 || !deadlines[0].Equal(second) || !deadlines[1].Equal(first) {
		t.Fatalf("deadline ordering: %+v", deadlines)
	}
	var config struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Rules) != 4 || config.Rules[0] != "DOMAIN,second.test,REJECT" || config.Rules[1] != "DOMAIN,duplicate.test,DIRECT" || config.Rules[2] != "DOMAIN,duplicate.test,DIRECT" {
		t.Fatalf("rule ordering: %+v", config.Rules)
	}
}
