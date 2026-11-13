package profile

import (
	"bytes"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Group is a proxy-group read from a Clash YAML file.
type Group struct {
	Name    string
	Type    string
	Now     string
	Proxies []Node
}

// Node is one proxy named by a group.
type Node struct {
	Name string
	Type string
}

type clashFile struct {
	Mode        string `yaml:"mode"`
	MixedPort   int    `yaml:"mixed-port"`
	ProxyGroups []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Now     string   `yaml:"now"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	Proxies []struct {
		Name string `yaml:"name"`
		Type string `yaml:"type"`
	} `yaml:"proxies"`
	Rules []string `yaml:"rules"`
}

// ParseConfig reads proxy groups, the mode, the mixed port and the rule count.
type Parsed struct {
	Mode      string
	MixedPort int
	Rules     int
	Groups    []Group
}

// ParseClashYAML reads a mihomo profile. An empty body is an empty parse.
func ParseClashYAML(data []byte) (Parsed, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Parsed{}, nil
	}
	var f clashFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return Parsed{}, err
	}
	types := map[string]string{}
	for _, p := range f.Proxies {
		types[p.Name] = p.Type
	}
	out := Parsed{Mode: f.Mode, MixedPort: f.MixedPort, Rules: len(f.Rules)}
	for _, g := range f.ProxyGroups {
		gg := Group{Name: g.Name, Type: g.Type, Now: g.Now}
		for _, name := range g.Proxies {
			gg.Proxies = append(gg.Proxies, Node{Name: name, Type: types[name]})
		}
		out.Groups = append(out.Groups, gg)
	}
	return out, nil
}

// SetMode rewrites the top-level mode key. Indented keys are left alone.
func SetMode(data []byte, mode string) []byte {
	if mode != "rule" && mode != "global" && mode != "direct" {
		mode = "rule"
	}
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("mode:")) {
			lines[i] = []byte("mode: " + mode)
			return bytes.Join(lines, []byte("\n"))
		}
	}
	return append([]byte("mode: "+mode+"\n"), data...)
}

// EnsureMixedPort prepends the Verge default mixed port when the file has none.
func EnsureMixedPort(data []byte, port int) []byte {
	if port <= 0 {
		port = 7897
	}
	if bytes.Contains(data, []byte("\nmixed-port:")) || bytes.HasPrefix(bytes.TrimSpace(data), []byte("mixed-port:")) {
		return data
	}
	head := []byte(fmt.Sprintf("mixed-port: %d\n", port))
	return append(head, data...)
}
