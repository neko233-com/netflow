package core

import C "github.com/metacubex/mihomo/constant"

// EmbeddedVersion is the mihomo release this binary vendors.
// The module's constant.Version stays "1.10.0" unless the linker
// overrides it, so Start reports EmbeddedVersion in that case.
const EmbeddedVersion = "1.19.33"

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
