package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestProfileDNSIsAppliedAndAgentPreviewExpiresOnChange(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: upstream, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		reply := new(mdns.Msg)
		reply.SetReply(req)
		if len(req.Question) > 0 {
			rr, _ := mdns.NewRR(req.Question[0].Name + " 30 IN A 192.0.2.42")
			reply.Answer = []mdns.RR{rr}
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	mixedPort := freePort(t)
	dnsSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr := dnsSocket.LocalAddr().String()
	_ = dnsSocket.Close()
	dir := t.TempDir()
	base := fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nlog-level: error\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n", mixedPort)
	path := filepath.Join(dir, "source.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	if err := a.ImportLocal(path); err != nil {
		t.Fatal(err)
	}
	id := a.model.CurrentProfile
	override := fmt.Sprintf("enable: true\nlisten: %s\nnameserver:\n  - %s\n", dnsAddr, upstream.LocalAddr().String())
	if err := a.setProfileDNS(id, true, override); err != nil {
		t.Fatal(err)
	}
	req := new(mdns.Msg)
	req.SetQuestion("netflow-test.invalid.", mdns.TypeA)
	var response *mdns.Msg
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		response, _, err = (&mdns.Client{Timeout: 150 * time.Millisecond}).Exchange(req, dnsAddr)
		if err == nil && len(response.Answer) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || response == nil || len(response.Answer) == 0 || response.Answer[0].(*mdns.A).A.String() != "192.0.2.42" {
		t.Fatalf("real DNS override did not answer: %v %v", response, err)
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	catalog.Items[0].Option.DNSVergeMerge = true
	catalog.Items[0].Option.DNSVergeHosts = "imported.example: 192.0.2.7\n"
	if err := a.profiles.Save(catalog); err != nil {
		t.Fatal(err)
	}
	if err := a.setProfileDNS(id, true, override); err != nil {
		t.Fatal(err)
	}
	catalog, err = a.profiles.Load()
	if err != nil || !catalog.Items[0].Option.DNSVergeMerge {
		t.Fatal("unchanged migrated DNS lost its merge semantics")
	}
	if err := a.setProfileDNS(id, true, override+"\n"); err != nil {
		t.Fatal(err)
	}
	catalog, err = a.profiles.Load()
	if err != nil || catalog.Items[0].Option.DNSVergeMerge || catalog.Items[0].Option.DNSVergeHosts == "" {
		t.Fatal("editing DNS did not preserve hosts and switch to the native override")
	}
	preview, err := a.agentPreview(agent.Change{Scope: "global", Operation: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.setProfileDNS(id, false, override); err != nil {
		t.Fatal(err)
	}
	if _, err := a.agentApply(preview.ProposalID); err == nil {
		t.Fatal("agent accepted stale preview after DNS change")
	}
	if err := a.setProfileDNS(id, true, "enable: not-a-bool"); err == nil {
		t.Fatal("invalid DNS config accepted")
	}
	calls := 0
	a.core.SetTransformer(func(data []byte, profileID string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("injected reload failure")
		}
		return a.applyProfileDNS(data, profileID)
	})
	if err := a.setProfileDNS(id, true, override); err == nil {
		t.Fatal("reload failure was ignored")
	}
	catalog, err = a.profiles.Load()
	if err != nil || catalog.Items[0].Option.DNSEnabled || calls != 2 {
		t.Fatalf("invalid override persisted: %+v %v", catalog, err)
	}
	original, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(original) != base {
		t.Fatalf("subscription was modified: %q %v", original, err)
	}
}

func TestMigratedDNSCompositionAndEditedOverride(t *testing.T) {
	base := []byte("dns:\n  enable: true\n  fallback: [9.9.9.9]\n  nameserver: [8.8.8.8]\n")
	option := dnsOverride{enabled: true, merge: true, text: "nameserver: [1.1.1.1]\n", hosts: "imported.example: 192.0.2.7\n"}
	merged, err := composeProfileDNS(base, option)
	if err != nil || !strings.Contains(string(merged), "9.9.9.9") || !strings.Contains(string(merged), "imported.example") {
		t.Fatalf("migration composition: %s %v", merged, err)
	}
	option.merge = false
	option.text = "enable: false\n"
	edited, err := composeProfileDNS(base, option)
	if err != nil || strings.Contains(string(edited), "9.9.9.9") || !strings.Contains(string(edited), "imported.example") {
		t.Fatalf("edited override: %s %v", edited, err)
	}
	option.enabled = false
	disabled, err := composeProfileDNS(base, option)
	if err != nil || string(disabled) != string(base) {
		t.Fatalf("disabled override: %s %v", disabled, err)
	}
}
