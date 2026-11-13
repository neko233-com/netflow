package service

import (
	"fmt"
	"strings"
)

// CommandRunner executes a program. Tests record the arguments.
type CommandRunner func(name string, args ...string) error

// AdminCommand is the osascript invocation Verge uses to install a daemon.
// The shell is not run here.
func AdminCommand(shell string) (string, []string) {
	escaped := strings.ReplaceAll(shell, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, escaped)
	return "osascript", []string{"-e", script}
}

// LaunchdPlist is the daemon definition copied into /Library/LaunchDaemons.
func LaunchdPlist(helper, socket, tokenFile string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-socket</string>
		<string>%s</string>
		<string>-token-file</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`, Label, helper, socket, tokenFile)
}

// InstallShell copies the helper, writes the plist and token, and bootstraps launchd.
func InstallShell(helperSrc, token string) string {
	plist := LaunchdPlist(HelperPath, SocketPath, TokenPath)
	// The plist is single-quoted in the shell so its XML quotes stay literal.
	return fmt.Sprintf(`set -e
mkdir -p /Library/PrivilegedHelperTools
cp %q %q
chmod 755 %q
printf %%s %q > %q
chmod 600 %q
cat > %q << 'PLIST'
%sPLIST
launchctl bootout system/%s >/dev/null 2>&1 || true
launchctl bootstrap system %q
`, helperSrc, HelperPath, HelperPath, token, TokenPath, TokenPath, PlistPath, plist, Label, PlistPath)
}

// UninstallShell removes the daemon, the binary, and the token.
func UninstallShell() string {
	return fmt.Sprintf(`set -e
launchctl bootout system/%s >/dev/null 2>&1 || true
rm -f %q %q %q %q
`, Label, HelperPath, PlistPath, TokenPath, SocketPath)
}
