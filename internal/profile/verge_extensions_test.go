package profile

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestComposeVergeRulesUsesVergeSequenceOrder(t *testing.T) {
	base := []byte("rules: ['DOMAIN,drop.test,DIRECT', 'MATCH,DIRECT']\n")
	ext := VergeExtensions{Rules: []byte("prepend: ['DOMAIN,first.test,DIRECT']\nappend: ['DOMAIN,last.test,DIRECT']\ndelete: ['DOMAIN,drop.test,DIRECT']\n")}
	output, err := ComposeVergeExtensions(base, ext)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(output, &parsed); err != nil {
		t.Fatal(err)
	}
	want := []string{"DOMAIN,first.test,DIRECT", "MATCH,DIRECT", "DOMAIN,last.test,DIRECT"}
	if !reflect.DeepEqual(parsed.Rules, want) {
		t.Fatalf("unexpected rule sequence: %v", parsed.Rules)
	}
}

func TestComposeVergeExtensionsSequencesAndMerges(t *testing.T) {
	base := []byte("proxies:\n  - {name: old, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: keep, type: socks5, server: 127.0.0.1, port: 2}\nproxy-groups:\n  - {name: Select, type: select, proxies: [old, keep, DIRECT]}\n  - {name: Gone, type: select, proxies: [old]}\ndns:\n  enable: true\n  nameserver: [9.9.9.9]\n  nameserver-policy: {old.example: [9.9.9.9]}\nhosts: {old.example: 192.0.2.1}\nprofile: {store-selected: true}\nrules: ['MATCH,DIRECT']\n")
	ext := VergeExtensions{
		Proxies:      []byte("prepend:\n  - {name: new, type: socks5, server: 127.0.0.1, port: 3}\nappend: []\ndelete: [old]\n"),
		Groups:       []byte("prepend: []\nappend:\n  - {name: Extra, type: select, proxies: [DIRECT]}\ndelete: [Gone]\n"),
		GlobalMerge:  []byte("profile: {store-fake-ip: true}\ndns:\n  nameserver-policy: {new.example: [1.1.1.1]}\nhosts: {new.example: 192.0.2.2}\n"),
		ProfileMerge: []byte("profile: {store-selected: false}\nlog-level: error\n"),
	}
	out, err := ComposeVergeExtensions(base, ext)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Proxies []struct {
			Name string `yaml:"name"`
		} `yaml:"proxies"`
		Groups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
		DNS struct {
			Enable     bool                `yaml:"enable"`
			Nameserver []string            `yaml:"nameserver"`
			Policy     map[string][]string `yaml:"nameserver-policy"`
		} `yaml:"dns"`
		Hosts   map[string]string `yaml:"hosts"`
		Profile struct {
			Selected bool `yaml:"store-selected"`
			Fake     bool `yaml:"store-fake-ip"`
		} `yaml:"profile"`
	}
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Proxies) != 2 || got.Proxies[0].Name != "new" || got.Proxies[1].Name != "keep" || len(got.Groups) != 2 || got.Groups[0].Name != "Select" || strings.Join(got.Groups[0].Proxies, ",") != "new,keep,DIRECT" || got.Groups[1].Name != "Extra" {
		t.Fatalf("incorrect proxy/group sequence: %s", out)
	}
	if !got.DNS.Enable || len(got.DNS.Nameserver) != 1 || len(got.DNS.Policy) != 1 || len(got.DNS.Policy["new.example"]) != 1 || got.DNS.Policy["new.example"][0] != "1.1.1.1" || got.Hosts["new.example"] != "192.0.2.2" || len(got.Hosts) != 1 || got.Profile.Selected || !got.Profile.Fake {
		t.Fatalf("incorrect merges: %s", out)
	}
	if !strings.Contains(string(base), "name: old") {
		t.Fatal("source subscription was modified")
	}
}

func TestComposeVergeExtensionsRejectsMalformedSequences(t *testing.T) {
	base := []byte("rules: ['MATCH,DIRECT']\n")
	for _, bad := range []string{"prepend: not-a-list", "delete: [1]", "prepend: ["} {
		if _, err := ComposeVergeExtensions(base, VergeExtensions{Proxies: []byte(bad)}); err == nil {
			t.Fatalf("accepted invalid extension %q", bad)
		}
	}
}

func TestComposeVergeExtensionsAcceptsCommentOnlyDefaults(t *testing.T) {
	base := []byte("rules: ['MATCH,DIRECT']\n")
	if _, err := ComposeVergeExtensions(base, VergeExtensions{GlobalMerge: []byte("# empty default\n"), Proxies: []byte("# empty sequence\n")}); err != nil {
		t.Fatal(err)
	}
}
