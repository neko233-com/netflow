package tun

import (
	"bytes"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEnsureDisabledHonorsMergedAndAliasedTUN(t *testing.T) {
	for _, input := range []string{
		"tun:\n  enable: true\n  auto-route: true\nmode: rule\n",
		"defaults: &tun\n  enable: true\n  auto-route: true\ntun: *tun\n",
		"defaults: &base\n  tun:\n    enable: true\n<<: *base\nmode: rule\n",
	} {
		output, err := EnsureDisabled([]byte(input))
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		var config struct {
			Tun struct {
				Enable bool `yaml:"enable"`
			} `yaml:"tun"`
		}
		if err = yaml.Unmarshal(output, &config); err != nil || config.Tun.Enable {
			t.Fatalf("TUN was not disabled: %s %v", output, err)
		}
	}
	unchanged := []byte("tun:\n  enable: false\nmode: rule\n")
	output, err := EnsureDisabled(unchanged)
	if err != nil || !bytes.Equal(output, unchanged) {
		t.Fatal("disabled configuration changed")
	}
}
