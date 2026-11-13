package sysproxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Runner runs one command and returns its combined output.
type Runner func(name string, args ...string) (string, error)

// System applies the proxy with networksetup and reads it back with scutil.
// Tests pass a Runner; NewSystem uses the real commands.
type System struct {
	Run Runner
}

// NewSystem returns a controller that talks to macOS. On other systems the
// commands fail if invoked; Platform selects Memory there.
func NewSystem() *System { return &System{Run: execRunner} }

func execRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Current reads scutil --proxy.
func (s *System) Current() (Settings, error) {
	if s == nil || s.Run == nil {
		return Settings{}, fmt.Errorf("sysproxy: no command runner")
	}
	out, err := s.Run("scutil", "--proxy")
	if err != nil {
		return Settings{}, err
	}
	return ParseScutil(out), nil
}

// Set enables or disables HTTP, HTTPS and SOCKS on every enabled network service.
func (s *System) Set(next Settings) error {
	if s == nil || s.Run == nil {
		return fmt.Errorf("sysproxy: no command runner")
	}
	services, err := s.services()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("sysproxy: no network services")
	}
	if !next.Enabled {
		for _, svc := range services {
			if err := s.setState(svc, false); err != nil {
				return err
			}
		}
		return nil
	}
	httpHost, httpPort, err := splitEndpoint(next.HTTP)
	if err != nil {
		return fmt.Errorf("sysproxy: http endpoint: %w", err)
	}
	socksHost, socksPort, err := splitEndpoint(next.SOCKS)
	if err != nil {
		return fmt.Errorf("sysproxy: socks endpoint: %w", err)
	}
	for _, svc := range services {
		if err := s.enable(svc, httpHost, httpPort, socksHost, socksPort); err != nil {
			return err
		}
	}
	return nil
}

func (s *System) services() ([]string, error) {
	out, err := s.Run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return ParseServices(out), nil
}

func (s *System) enable(service, httpHost, httpPort, socksHost, socksPort string) error {
	steps := [][]string{
		{"-setwebproxy", service, httpHost, httpPort},
		{"-setsecurewebproxy", service, httpHost, httpPort},
		{"-setsocksfirewallproxy", service, socksHost, socksPort},
		{"-setproxybypassdomains", service, "127.0.0.1", "localhost", "*.local", "<local>"},
		{"-setwebproxystate", service, "on"},
		{"-setsecurewebproxystate", service, "on"},
		{"-setsocksfirewallproxystate", service, "on"},
	}
	for _, args := range steps {
		if _, err := s.Run("networksetup", args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *System) setState(service string, on bool) error {
	state := "off"
	if on {
		state = "on"
	}
	for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
		if _, err := s.Run("networksetup", flag, service, state); err != nil {
			return err
		}
	}
	return nil
}

func splitEndpoint(endpoint string) (host, port string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	h, p, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", "", err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("bad port %q", p)
	}
	if h == "" {
		return "", "", fmt.Errorf("empty host")
	}
	return h, p, nil
}

// ParseServices reads `networksetup -listallnetworkservices`.
// The header line and services prefixed with * (disabled) are dropped.
func ParseServices(out string) []string {
	var svcs []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i == 0 && strings.Contains(line, "asterisk") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs
}

// ParseScutil reads `scutil --proxy`. Enabled is true when HTTP, HTTPS or
// SOCKS is on. HTTP prefers the HTTP proxy, then HTTPS. SOCKS is the SOCKS proxy.
func ParseScutil(out string) Settings {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	httpOn := vals["HTTPEnable"] == "1"
	httpsOn := vals["HTTPSEnable"] == "1"
	socksOn := vals["SOCKSEnable"] == "1"
	var st Settings
	st.Enabled = httpOn || httpsOn || socksOn
	st.SchemeSpecific = true
	if httpOn {
		st.HTTP = joinProxy(vals["HTTPProxy"], vals["HTTPPort"])
	}
	if httpsOn {
		st.HTTPS = joinProxy(vals["HTTPSProxy"], vals["HTTPSPort"])
	}
	if socksOn {
		st.SOCKS = joinProxy(vals["SOCKSProxy"], vals["SOCKSPort"])
	}
	return st
}

func joinProxy(host, port string) string {
	if host == "" || port == "" {
		return ""
	}
	return net.JoinHostPort(host, port)
}
