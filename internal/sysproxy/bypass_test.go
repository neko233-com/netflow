package sysproxy

import "testing"

func TestFormatBypass(t *testing.T) {
	t.Parallel()
	const mac = "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,*.crashlytics.com,<local>"
	const linux = "localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,::1"
	const windows = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;*.local;<local>"

	if got := FormatBypass("darwin", "", true); got != mac {
		t.Fatalf("mac default %q", got)
	}
	if got := FormatBypass("darwin", "", false); got != mac {
		t.Fatalf("empty custom still uses the default, got %q", got)
	}
	if got := FormatBypass("darwin", "example.com", true); got != mac+",example.com" {
		t.Fatalf("mac default plus custom %q", got)
	}
	if got := FormatBypass("darwin", "example.com", false); got != "example.com" {
		t.Fatalf("mac custom only %q", got)
	}

	if got := FormatBypass("linux", "example.com", true); got != linux+",example.com" {
		t.Fatalf("linux join %q", got)
	}
	if got := FormatBypass("freebsd", "", true); got != linux {
		t.Fatalf("non-windows non-darwin list %q", got)
	}
	if got := FormatBypass("windows", "example.com", true); got != windows+";example.com" {
		t.Fatalf("windows join %q", got)
	}
	if got := FormatBypass("windows", "example.com", false); got != "example.com" {
		t.Fatalf("windows custom only %q", got)
	}
}
