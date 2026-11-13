package core

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	mihomodns "github.com/metacubex/mihomo/dns"
	"github.com/miekg/dns"
)

func TestFakeIPStateRestoresBeforeDNSListenerStarts(t *testing.T) {
	previous := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = nil
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	dir := t.TempDir()
	config := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nipv6: false\ndns:\n  enable: true\n  listen: '%s'\n  enhanced-mode: fake-ip\n  nameserver: ['127.0.0.1:9']\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", address)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	t.Cleanup(func() { _ = c.Stop() })
	lookup := func(name string) string {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		answer, _, err := (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).Exchange(query, address)
		if err != nil || len(answer.Answer) == 0 {
			t.Fatalf("DNS %s: %v", name, err)
		}
		record, ok := answer.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("unexpected DNS answer: %+v", answer.Answer)
		}
		return record.A.String()
	}
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	a, b := lookup("a.example."), lookup("b.example.")
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	state, err := c.ExportFakeIPState()
	if err != nil || state == nil {
		t.Fatalf("export: %+v %v", state, err)
	}
	mapper := resolver.DefaultHostMapper.(*mihomodns.ResolverEnhancer)
	if err := mapper.FlushFakeIP(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	_ = lookup("stale.example.")
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.StageFakeIPState(state); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	if got := lookup("b.example."); got != b {
		t.Fatalf("b mapping changed: %s != %s", got, b)
	}
	if got := lookup("a.example."); got != a {
		t.Fatalf("a mapping changed: %s != %s", got, a)
	}
}
