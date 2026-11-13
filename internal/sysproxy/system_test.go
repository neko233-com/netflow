package sysproxy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseServicesSkipsHeaderAndDisabled(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n"
	got := ParseServices(out)
	want := []string{"Wi-Fi", "USB 10/100/1000 LAN"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("services %q", got)
	}
}

func TestParseScutil(t *testing.T) {
	out := `
<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7897
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7897
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 7897
  SOCKSProxy : 127.0.0.1
}
`
	got := ParseScutil(out)
	if !got.Enabled || got.HTTP != "127.0.0.1:7897" || got.SOCKS != "127.0.0.1:7897" {
		t.Fatalf("%+v", got)
	}
	if !got.SchemeSpecific || got.HTTPS != "127.0.0.1:7897" {
		t.Fatalf("missing HTTPS proxy: %+v", got)
	}
	httpsOnly := ParseScutil("HTTPSEnable : 1\nHTTPSProxy : 127.0.0.1\nHTTPSPort : 7777\n")
	if !httpsOnly.Enabled || !httpsOnly.SchemeSpecific || httpsOnly.HTTP != "" || httpsOnly.HTTPS != "127.0.0.1:7777" {
		t.Fatalf("HTTPS-only proxy: %+v", httpsOnly)
	}
	off := ParseScutil("HTTPEnable : 0\nHTTPSEnable : 0\nSOCKSEnable : 0\n")
	if off.Enabled {
		t.Fatal("disabled proxy parsed as on")
	}
}

func TestSystemSetAndCurrent(t *testing.T) {
	var calls []string
	s := &System{Run: func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "networksetup" && len(args) > 0 && args[0] == "-listallnetworkservices" {
			return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bridge\n", nil
		}
		if name == "scutil" {
			return "HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 7897\nSOCKSEnable : 1\nSOCKSProxy : 127.0.0.1\nSOCKSPort : 7897\n", nil
		}
		return "", nil
	}}
	if err := s.Set(Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		"networksetup -setwebproxy Wi-Fi 127.0.0.1 7897",
		"networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 7897",
		"networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 7897",
		"networksetup -setwebproxystate Wi-Fi on",
		"networksetup -setsocksfirewallproxystate Wi-Fi on",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "Bridge") {
		t.Fatal("disabled service was configured")
	}
	cur, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.Enabled || cur.HTTP != "127.0.0.1:7897" {
		t.Fatalf("current %+v", cur)
	}

	calls = nil
	if err := s.Set(Settings{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	off := strings.Join(calls, "\n")
	if !strings.Contains(off, "networksetup -setwebproxystate Wi-Fi off") || !strings.Contains(off, "networksetup -setsocksfirewallproxystate Wi-Fi off") {
		t.Fatalf("disable commands:\n%s", off)
	}
}

func TestSystemSetRejectsBadEndpoint(t *testing.T) {
	s := &System{Run: func(name string, args ...string) (string, error) {
		if name == "networksetup" && args[0] == "-listallnetworkservices" {
			return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n", nil
		}
		return "", nil
	}}
	if err := s.Set(Settings{Enabled: true, HTTP: "not-a-host", SOCKS: "127.0.0.1:7897"}); err == nil {
		t.Fatal("bad endpoint was accepted")
	}
}

func TestSystemSurfacesCommandError(t *testing.T) {
	s := &System{Run: func(string, ...string) (string, error) {
		return "", errors.New("denied")
	}}
	if err := s.Set(Settings{Enabled: true, HTTP: "127.0.0.1:7897", SOCKS: "127.0.0.1:7897"}); err == nil {
		t.Fatal("expected command error")
	}
}
