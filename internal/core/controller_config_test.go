package core

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
)

func TestSuppressExternalControllerPreservesNestedYAMLAndOverridesMerge(t *testing.T) {
	input := []byte(`defaults: &defaults
  external-controller: 127.0.0.1:9090
  external-controller-unix: controller.sock
  external-ui: dashboard
<<: *defaults
external-controller-cors:
  allow-origins:
    - https://example.test
rules:
  - MATCH,DIRECT
`)
	suppressed, err := suppressExternalController(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(suppressed), "allow-origins") || !strings.Contains(string(suppressed), "example.test") {
		t.Fatalf("nested configuration lost: %s", suppressed)
	}
	cfg, err := executor.ParseWithBytes(suppressed)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Controller.ExternalController != "" || cfg.Controller.ExternalControllerUnix != "" || cfg.Controller.ExternalUI != "" {
		t.Fatalf("controller suppression failed: %+v", cfg.Controller)
	}
}
