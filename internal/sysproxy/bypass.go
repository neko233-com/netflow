package sysproxy

// Default bypass lists and the join separator follow Clash Verge Rev
// v2.5.9 format_bypass (SYS-03, SYS-04). An empty custom list keeps the
// platform default even when useDefault is false. Otherwise useDefault
// joins default + separator + custom, and a false useDefault keeps custom
// alone. Windows joins with ';'; macOS and Linux join with ','.
// Any other goos uses the Linux list.

const (
	bypassDarwin  = "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,*.crashlytics.com,<local>"
	bypassLinux   = "localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,::1"
	bypassWindows = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;*.local;<local>"
)

// FormatBypass builds the system-proxy bypass string for goos.
// goos is a runtime.GOOS value ("darwin", "linux", "windows").
func FormatBypass(goos, custom string, useDefault bool) string {
	def, sep := bypassList(goos)
	if custom == "" {
		return def
	}
	if !useDefault {
		return custom
	}
	return def + sep + custom
}

func bypassList(goos string) (list, sep string) {
	switch goos {
	case "windows":
		return bypassWindows, ";"
	case "darwin":
		return bypassDarwin, ","
	default:
		return bypassLinux, ","
	}
}
