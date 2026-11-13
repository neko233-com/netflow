package tun

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestComposeTUNUsesExplicitChoiceWithoutChangingSubscription(t *testing.T) {
	base := []byte("defaults: &d\n  enable: true\n  device: OtherApp\n  auto-route: false\n  auto-detect-interface: false\ntun: *d\ndns:\n  enable: false\nrules: ['MATCH,DIRECT']\n")
	off, err := Compose(base, false, "NetFlow")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Tun struct {
			Enable     bool   `yaml:"enable"`
			Device     string `yaml:"device"`
			AutoRoute  bool   `yaml:"auto-route"`
			AutoDetect bool   `yaml:"auto-detect-interface"`
		} `yaml:"tun"`
	}
	if err = yaml.Unmarshal(off, &parsed); err != nil || parsed.Tun.Enable {
		t.Fatal("TUN remained enabled")
	}
	on, err := Compose(base, true, "NetFlow")
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(on, &parsed); err != nil || !parsed.Tun.Enable || parsed.Tun.Device != "NetFlow" || !parsed.Tun.AutoRoute || !parsed.Tun.AutoDetect {
		t.Fatalf("TUN choice missing: %+v %v", parsed, err)
	}
	if !strings.Contains(string(base), "OtherApp") || !strings.Contains(string(base), "tun: *d") {
		t.Fatal("source configuration was modified")
	}
	if _, err = Compose([]byte("tun: [bad]"), true, "NetFlow"); err == nil {
		t.Fatal("invalid TUN mapping accepted")
	}
}
