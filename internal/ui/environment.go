package ui

import "strings"

// ProxyEnvironment returns commands for the shell selected in preferences.
func ProxyEnvironment(shell, endpoint string) string {
	addr := "http://" + endpoint
	vars := []string{"http_proxy", "https_proxy", "all_proxy"}
	lines := make([]string, 0, len(vars))
	for _, name := range vars {
		switch shell {
		case "fish":
			lines = append(lines, "set -gx "+name+" '"+addr+"'")
		case "nushell":
			lines = append(lines, "$env."+name+" = '"+addr+"'")
		case "cmd":
			lines = append(lines, "set \""+name+"="+addr+"\"")
		case "powershell":
			lines = append(lines, "$env:"+name+" = '"+addr+"'")
		default:
			lines = append(lines, "export "+name+"='"+addr+"'")
		}
	}
	return strings.Join(lines, "\n")
}
