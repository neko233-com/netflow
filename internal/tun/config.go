package tun

import (
	"fmt"
	"os"

	"github.com/metacubex/mihomo/constant/features"

	"go.yaml.in/yaml/v3"
)

// Verge defaults for a tun block that does not already name them.
// stack is constants.tun.DEFAULT_STACK ("mips"), auto-route is true,
// and dns-hijack is ["any:53"].
const (
	DefaultStack     = "mips"
	DefaultDNSHijack = "any:53"
)

// SupportedStacks reports the stacks compiled into this binary.
func SupportedStacks() []string {
	if features.WithGVisor {
		return []string{"system", "mixed", "gvisor", "mips"}
	}
	return []string{"system", "mips"}
}

// StackLabel is the tun dialog name for a yaml stack value.
// mihomo v1.19.33 accepts "mips" and reports it as "Mips".
func StackLabel(yaml string) string {
	switch yaml {
	case "system", "System":
		return "System"
	case "gvisor", "gVisor":
		return "gVisor"
	case "mixed", "Mixed":
		return "Mixed"
	case "mips", "Mips":
		return "Mips"
	default:
		return "Mips"
	}
}

// ErrNeedService is returned when TUN cannot be turned on because the
// process is not allowed to open the device.
var ErrNeedService = fmt.Errorf("TUN 暂不可用：缺少特权内核或管理员授权")

// Use applies Verge use_tun plus the template tun defaults.
// enable true sets tun.enable and, when missing, stack, auto-route, and
// dns-hijack. When DNS enhanced-mode is missing or fake-ip, DNS is forced
// on with the fake-ip range. enable false only sets tun.enable to false.
func Use(cfg map[string]any, enable bool) map[string]any {
	out := cloneMap(cfg)
	tun := mapAny(out["tun"])
	if enable {
		if _, ok := tun["stack"]; !ok {
			tun["stack"] = DefaultStack
		}
		if _, ok := tun["auto-route"]; !ok {
			tun["auto-route"] = true
		}
		if _, ok := tun["dns-hijack"]; !ok {
			tun["dns-hijack"] = []any{DefaultDNSHijack}
		}
		ensureFakeIP(out)
	}
	tun["enable"] = enable
	out["tun"] = tun
	return out
}

func ensureFakeIP(cfg map[string]any) {
	dns := mapAny(cfg["dns"])
	mode, _ := dns["enhanced-mode"].(string)
	if mode != "" && mode != "fake-ip" {
		cfg["dns"] = dns
		return
	}
	dns["enable"] = true
	if _, ok := dns["ipv6"]; !ok {
		if v, ok := cfg["ipv6"].(bool); ok {
			dns["ipv6"] = v
		}
	}
	if mode == "" {
		dns["enhanced-mode"] = "fake-ip"
	}
	if _, ok := dns["fake-ip-range"]; !ok {
		dns["fake-ip-range"] = "198.18.0.1/16"
	}
	if ipv6, _ := cfg["ipv6"].(bool); ipv6 {
		if _, ok := dns["fake-ip-range6"]; !ok {
			dns["fake-ip-range6"] = "2001:2::0/64"
		}
	}
	cfg["dns"] = dns
}

// ApplyFile rewrites a mihomo YAML file with Use. It does not start the kernel.
func ApplyFile(path string, enable bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	out, err := yaml.Marshal(Use(cfg, enable))
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func mapAny(v any) map[string]any {
	m, _ := v.(map[string]any)
	return cloneMap(m)
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
