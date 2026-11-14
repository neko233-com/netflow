package profile

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRestoreVergeManagedFieldsRetainsRuntimeControlsAndProviderOrder(t *testing.T) {
	base := []byte("mixed-port: 7897\nmode: rule\ntun: {enable: false, auto-route: true}\nsecret: original\nrules: ['MATCH,DIRECT']\n")
	scripted := []byte("mixed-port: 9999\nmode: global\ntun: {enable: true, auto-route: false}\nsecret: leaked\nexternal-controller: '0.0.0.0:9090'\nproxy-providers: {z: {}, a: {}}\nrules: ['DOMAIN,example.test,DIRECT', 'MATCH,DIRECT']\n")
	result, err := RestoreVergeManagedFields(context.Background(), scripted, base)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Mixed int    `yaml:"mixed-port"`
		Mode  string `yaml:"mode"`
		TUN   struct {
			Enable    bool `yaml:"enable"`
			AutoRoute bool `yaml:"auto-route"`
		} `yaml:"tun"`
		Secret   string   `yaml:"secret"`
		External string   `yaml:"external-controller"`
		Rules    []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(result, &config); err != nil {
		t.Fatal(err)
	}
	if config.Mixed != 7897 || config.Mode != "rule" || config.TUN.Enable || !config.TUN.AutoRoute || config.Secret != "original" || config.External != "" || len(config.Rules) != 2 || config.Rules[0] != "DOMAIN,example.test,DIRECT" {
		t.Fatalf("managed fields incorrect: %+v", config)
	}
	if bytes.Index(result, []byte(`"z"`)) >= bytes.Index(result, []byte(`"a"`)) {
		t.Fatal("provider order changed")
	}
}

func TestRestoreVergeManagedFieldsRejectsInvalidInputAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RestoreVergeManagedFields(ctx, []byte("{}"), []byte("{}")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	if _, err := RestoreVergeManagedFields(context.Background(), []byte("rules: ["), []byte("{}")); err == nil {
		t.Fatal("invalid output accepted")
	}
}
