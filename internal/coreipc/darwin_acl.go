package coreipc

import "strings"

// darwinACLAbsent parses fixed-path `ls -ldne` output. ACL entries are
// additional lines, and '+' in the mode is an ACL indicator. Extended
// attributes alone may instead add '@' to the mode.
func darwinACLAbsent(output []byte) bool {
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 9 {
		return false
	}
	mode := fields[0]
	return mode[0] == 'd' && (len(mode) == 10 || (len(mode) == 11 && mode[10] == '@'))
}
