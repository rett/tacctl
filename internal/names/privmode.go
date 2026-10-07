package names

// The modes of a Cisco privilege mapping (tacctl 0.2.2, docs/plans/
// 0.2.2-plan.md §5.6): an entry of privileges.<group> may start with
// 'exec:', 'exec all:', 'configure:' or 'configure all:'; an entry without
// one is 'exec:', as every entry was before 0.2.2.

import (
	"fmt"
	"strings"
)

// PrivModes are the modes an entry may name, in the order they are shown.
var PrivModes = []string{"exec", "exec all", "configure", "configure all"}

// PrivModeExec is the mode of an entry that names none.
const PrivModeExec = "exec"

// SplitPrivEntry splits a privilege entry into its mode and its command:
// "configure all: router bgp" is ("configure all", "router bgp"), "show
// version" is ("exec", "show version"). ok is false when the entry has a
// prefix that is no mode (mode is then the prefix as written).
func SplitPrivEntry(entry string) (mode, cmd string, ok bool) {
	prefix, rest, found := strings.Cut(entry, ":")
	if !found {
		return PrivModeExec, entry, true
	}
	mode = strings.Join(strings.Fields(prefix), " ")
	for _, m := range PrivModes {
		if m == mode {
			return mode, strings.TrimSpace(rest), true
		}
	}
	return strings.TrimSpace(prefix), strings.TrimSpace(rest), false
}

// PrivEntry is the stored form of a mapping: the command alone for exec,
// '<mode>: <command>' for the other modes.
func PrivEntry(mode, cmd string) string {
	if mode == PrivModeExec {
		return cmd
	}
	return mode + ": " + cmd
}

// ValidatePrivEntry is ValidatePrivCommandString for an entry that may
// start with a mode; it returns the entry in its stored form.
func ValidatePrivEntry(entry string) (string, error) {
	mode, cmd, ok := SplitPrivEntry(entry)
	if !ok {
		return "", fail(
			fmt.Sprintf("Unknown privilege mode '%s' in '%s'.", mode, entry),
			"Start the entry with exec:, exec all:, configure: or configure all: (none means exec:).",
		)
	}
	if err := ValidatePrivCommandString(cmd); err != nil {
		return "", err
	}
	return PrivEntry(mode, cmd), nil
}
