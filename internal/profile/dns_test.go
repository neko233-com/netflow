package profile

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestComposeDNSOverridesMergedAndKeepsInput(t *testing.T) {
	base := []byte("defaults: &d\n  dns:\n    enable: false\n<<: *d\nrules:\n  - MATCH,DIRECT\n")
	out, err := ComposeDNS(base, "enable: true\nlisten: 127.0.0.1:1053\nnameserver: [1.1.1.1]\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "listen: 127.0.0.1:1053") || !strings.Contains(string(base), "enable: false") {
		t.Fatal("override missing or original changed")
	}
	for _, bad := range []string{"", "[]", "dns: [", strings.Repeat("x", 65537)} {
		if _, err := ComposeDNS(base, bad); err == nil {
			t.Fatalf("invalid override accepted: %.20q", bad)
		}
	}
}

func TestComposeVergeDNSPreservesFieldsAndHosts(t *testing.T) {
	base := []byte("dns:\n  enable: true\n  ipv6: true\n  enhanced-mode: fake-ip\n  nameserver: [8.8.8.8]\n  fallback: [9.9.9.9]\n  use-hosts: true\nhosts: {old.example: 192.0.2.1}\n")
	out, err := ComposeVergeDNS(base, "enable: false\nnameserver: [1.1.1.1]\nfallback: []\n", "new.example: 192.0.2.2\n")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Enable     bool     `yaml:"enable"`
			Nameserver []string `yaml:"nameserver"`
			Fallback   []string `yaml:"fallback"`
			Range6     string   `yaml:"fake-ip-range6"`
			UseHosts   bool     `yaml:"use-hosts"`
		} `yaml:"dns"`
		Hosts map[string]string `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !got.DNS.Enable || !got.DNS.UseHosts || len(got.DNS.Nameserver) != 1 || got.DNS.Nameserver[0] != "1.1.1.1" || len(got.DNS.Fallback) != 1 || got.DNS.Fallback[0] != "9.9.9.9" || got.DNS.Range6 != "2001:2::0/64" || len(got.Hosts) != 1 || got.Hosts["new.example"] != "192.0.2.2" {
		t.Fatalf("unexpected migrated DNS: %+v\n%s", got, out)
	}
	if !strings.Contains(string(base), "old.example") {
		t.Fatal("source subscription was modified")
	}
	for _, bad := range []string{"[]", "nameserver: [", "x: 1\nx: 2\n", strings.Repeat("x", 65537)} {
		if _, err := ComposeVergeDNS(base, bad, ""); err == nil {
			t.Fatalf("invalid override accepted: %.20q", bad)
		}
	}
}

func TestComposeVergeDNSPreservesInheritedDNS(t *testing.T) {
	base := []byte("defaults: &defaults\n  dns:\n    enable: true\n    fallback: [9.9.9.9]\n<<: *defaults\nrules: ['MATCH,DIRECT']\n")
	out, err := ComposeVergeDNS(base, "nameserver: [1.1.1.1]\n", "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Enable     bool     `yaml:"enable"`
			Fallback   []string `yaml:"fallback"`
			Nameserver []string `yaml:"nameserver"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !got.DNS.Enable || len(got.DNS.Fallback) != 1 || len(got.DNS.Nameserver) != 1 {
		t.Fatalf("inherited DNS was lost: %s", out)
	}
}

func TestComposeVergeDNSPreservesAliasedDNS(t *testing.T) {
	base := []byte("dns_defaults: &dns_defaults\n  enable: true\n  fallback: [9.9.9.9]\ndns: *dns_defaults\nrules: ['MATCH,DIRECT']\n")
	out, err := ComposeVergeDNS(base, "nameserver: [1.1.1.1]\n", "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Enable     bool     `yaml:"enable"`
			Fallback   []string `yaml:"fallback"`
			Nameserver []string `yaml:"nameserver"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !got.DNS.Enable || len(got.DNS.Fallback) != 1 || len(got.DNS.Nameserver) != 1 {
		t.Fatalf("aliased DNS was lost: %s", out)
	}
}

func TestComposeVergeDNSDoesNotAlterOtherAnchorUsers(t *testing.T) {
	base := []byte("dns: &shared\n  enable: true\n  fallback: [9.9.9.9]\nother: *shared\nrules: ['MATCH,DIRECT']\n")
	out, err := ComposeVergeDNS(base, "nameserver: [1.1.1.1]\n", "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Nameserver []string `yaml:"nameserver"`
			Fallback   []string `yaml:"fallback"`
		} `yaml:"dns"`
		Other struct {
			Nameserver []string `yaml:"nameserver"`
			Fallback   []string `yaml:"fallback"`
		} `yaml:"other"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.DNS.Nameserver) != 1 || len(got.DNS.Fallback) != 1 || len(got.Other.Nameserver) != 0 || len(got.Other.Fallback) != 1 {
		t.Fatalf("anchor users changed: %s", out)
	}
}

func TestComposeVergeDNSResolvesNestedAndHostsAliases(t *testing.T) {
	base := []byte("dns:\n  nameserver: &ns [8.8.8.8]\nother_nameservers: *ns\nhosts: &host_map {old.example: 192.0.2.1}\nother_hosts: *host_map\nrules: ['MATCH,DIRECT']\n")
	out, err := ComposeVergeDNS(base, "nameserver: [1.1.1.1]\n", "new.example: 192.0.2.2\n")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Nameserver []string `yaml:"nameserver"`
		} `yaml:"dns"`
		OtherNameservers []string          `yaml:"other_nameservers"`
		Hosts            map[string]string `yaml:"hosts"`
		OtherHosts       map[string]string `yaml:"other_hosts"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.DNS.Nameserver) != 1 || got.DNS.Nameserver[0] != "1.1.1.1" || len(got.OtherNameservers) != 1 || got.OtherNameservers[0] != "8.8.8.8" || got.Hosts["new.example"] != "192.0.2.2" || got.OtherHosts["old.example"] != "192.0.2.1" {
		t.Fatalf("alias users changed: %s", out)
	}
}

func TestComposeVergeDNSPreservesPolicyOrderAndMergePrecedence(t *testing.T) {
	base := []byte("dns:\n  enable: true\n  nameserver-policy:\n    z.example: [9.9.9.9]\n    a.example: [8.8.8.8]\nother: &value [1]\nalias: *value\n")
	override := "defaults: &defaults\n  nameserver: [8.8.8.8]\n  fallback: [9.9.9.9]\n<<: *defaults\nnameserver: [1.1.1.1]\nnameserver-policy:\n  z.example: [1.1.1.1]\n  a.example: [2.2.2.2]\n"
	out, err := ComposeVergeDNS(base, override, "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Nameserver []string `yaml:"nameserver"`
			Fallback   []string `yaml:"fallback"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.DNS.Nameserver) != 1 || got.DNS.Nameserver[0] != "1.1.1.1" || len(got.DNS.Fallback) != 1 || got.DNS.Fallback[0] != "9.9.9.9" {
		t.Fatalf("incorrect YAML merge: %s", out)
	}
	z, a := strings.Index(string(out), "z.example:"), strings.Index(string(out), "a.example:")
	if z < 0 || a < 0 || z >= a {
		t.Fatalf("DNS policy order changed: %s", out)
	}
}
