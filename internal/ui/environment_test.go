package ui

import (
	"strings"
	"testing"
)

func TestProxyEnvironmentUsesSelectedShell(t *testing.T) {
	for shell, want := range map[string]string{"bash": "export http_proxy=", "fish": "set -gx http_proxy", "nushell": "$env.http_proxy =", "cmd": "set \"http_proxy=", "powershell": "$env:http_proxy ="} {
		got := ProxyEnvironment(shell, "127.0.0.1:7897")
		if !strings.Contains(got, want) || !strings.Contains(got, "https_proxy") || !strings.Contains(got, "all_proxy") {
			t.Fatalf("%s: %s", shell, got)
		}
	}
}
