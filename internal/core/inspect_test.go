package core

import (
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

func TestMapConnection(t *testing.T) {
	info := &statistic.TrackerInfo{
		Metadata: &C.Metadata{
			Host:    "example.com",
			DstPort: 443,
			Process: "Safari",
			NetWork: C.TCP,
			Type:    C.HTTPS,
			SrcIP:   netip.MustParseAddr("127.0.0.1"),
			SrcPort: 52311,
		},
		Rule:        "DomainSuffix",
		RulePayload: "example.com",
		Chain:       C.Chain{"HK", "Proxy"},
		Start:       time.Unix(10, 0).UTC(),
	}
	info.UploadTotal.Store(10)
	info.DownloadTotal.Store(20)
	it := mapConnection(info)
	if it.Host != "example.com" || it.DestinationPort != "443" || it.Process != "Safari" {
		t.Fatalf("%+v", it)
	}
	if it.Upload != 10 || it.Download != 20 || it.Network != "tcp" || it.Type != "HTTPS" {
		t.Fatalf("%+v", it)
	}
	if it.SourceIP != "127.0.0.1" || it.SourcePort != "52311" || len(it.Chains) != 2 {
		t.Fatalf("%+v", it)
	}
}

func TestInspectWhileStopped(t *testing.T) {
	c := New()
	if items, _, _ := c.Connections(); items != nil {
		t.Fatalf("connections %+v", items)
	}
	if c.Rules() != nil || c.RuleProviders() != nil {
		t.Fatal("stopped core returned rules")
	}
	if err := c.CloseAllConnections(); err == nil {
		t.Fatal("close all on a stopped core succeeded")
	}
	if err := c.UpdateAllRuleProviders(); err == nil {
		t.Fatal("update all with no providers succeeded")
	}
}
