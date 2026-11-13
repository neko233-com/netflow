package core

import (
	"runtime/debug"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

// EmbeddedVersion is derived from Go's build information so it follows the
// actual replacement module used by this binary.
var EmbeddedVersion = embeddedVersion()

func embeddedVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return mihomoDependencyVersion(info)
}

func mihomoDependencyVersion(info *debug.BuildInfo) string {
	if info != nil {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/metacubex/mihomo" {
				continue
			}
			if dep.Replace != nil {
				if dep.Replace.Version == "" || dep.Replace.Version == "(devel)" {
					return "local"
				}
				return strings.TrimPrefix(dep.Replace.Version, "v")
			}
			return strings.TrimPrefix(dep.Version, "v")
		}
	}
	return "unknown"
}

func init() {
	if C.Version == "" || C.Version == "1.10.0" {
		C.Version = EmbeddedVersion
	}
}

// Version is the kernel version the external controller would report.
func Version() string {
	if C.Version == "" {
		return EmbeddedVersion
	}
	return C.Version
}
