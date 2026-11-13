package tun

import "strings"

// conflictsWithTUN recognizes common active tunnel drivers. This is a
// conservative heuristic, not proof that all route conflicts are detected.
func conflictsWithTUN(name, description string, up bool) bool {
	if !up || strings.EqualFold(strings.TrimSpace(name), DeviceName()) {
		return false
	}
	d := strings.ToLower(description)
	for _, marker := range []string{"meta tunnel", "wintun", "wireguard tunnel", "sing-tun"} {
		if strings.Contains(d, marker) {
			return true
		}
	}
	return false
}
