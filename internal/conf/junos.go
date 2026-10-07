package conf

// The per-group device settings of tacctl 0.2.2 in tacctl.yaml (decision
// D2 of docs/plans/0.2.2-plan.md): junos.<group>.deny_commands and
// .deny_configuration (lists of POSIX EREs the server sends to Junos at
// login), wti_level.<group> (a WTI access level instead of the priv-lvl
// band) and tier.<group> (the group's tacctl tier instead of the priv-lvl
// band). Nothing here has a default: an absent key is "not set".

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/py"
)

// The Junos attributes a group may set, as tacctl.yaml names them.
const (
	JunosDenyCommands      = "deny_commands"
	JunosDenyConfiguration = "deny_configuration"
)

// JunosAttrs are the Junos attributes in the order they are shown and
// sent.
var JunosAttrs = []string{JunosDenyCommands, JunosDenyConfiguration}

// WTILevels are the WTI access levels, lowest first.
var WTILevels = []string{"viewonly", "user", "superuser", "administrator"}

// Tiers are the tacctl tiers a group may be given, lowest first.
var Tiers = []string{"readonly", "operator", "engineer", "superuser"}

// JunosArg is the attribute's name on the wire (TACACS+ argument and
// Juniper RADIUS VSA): deny-commands, deny-configuration.
func JunosArg(attr string) string { return strings.ReplaceAll(attr, "_", "-") }

// JunosLimit is the longest value the attribute may carry, in bytes:
// TACACS+ sends '<arg>=<value>' in one argument of at most 255 bytes, and
// Junos refuses a login whose argument is longer (241 for deny-commands,
// 236 for deny-configuration). RADIUS's 253 never binds first.
func JunosLimit(attr string) int { return 255 - len(JunosArg(attr)) - 1 }

// JunosValue is the one value a list of patterns is sent as: each item in
// parentheses, joined by '|'. Nothing for no items.
func JunosValue(items []string) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = "(" + it + ")"
	}
	return strings.Join(parts, "|")
}

// JunosItemProblem is what is wrong with one pattern ("" when nothing):
// empty, not a regex, or a Perl-style '(?' that POSIX ERE (and so Junos)
// does not know.
func JunosItemProblem(item string) string {
	switch {
	case strings.TrimSpace(item) == "":
		return "is empty"
	case strings.Contains(item, "(?"):
		return "uses '(?', which is not POSIX ERE (Junos refuses it)"
	}
	if _, err := regexp.Compile(item); err != nil {
		return "is not a valid regular expression"
	}
	return ""
}

// junosListProblem is the junos_regex_list branch of Validate for
// junos.<group>.<attr>.
func junosListProblem(path string, value any) string {
	attr := path[strings.LastIndex(path, ".")+1:]
	if !slices.Contains(JunosAttrs, attr) {
		if strings.HasPrefix(attr, "allow_") {
			return attr + " is not supported in this release (only deny_commands and deny_configuration)"
		}
		return "must be deny_commands or deny_configuration"
	}
	items, isList := py.List(value)
	if !isList {
		return "must be a list of regular expressions"
	}
	strs := make([]string, 0, len(items))
	for i, item := range items {
		s, isStr := item.(string)
		if !isStr {
			return fmt.Sprintf("element %d: must be a string", i)
		}
		if why := JunosItemProblem(s); why != "" {
			return fmt.Sprintf("element %d: %s %s", i, py.ReprString(s), why)
		}
		if slices.Contains(strs, s) {
			return fmt.Sprintf("element %d: %s is listed twice", i, py.ReprString(s))
		}
		strs = append(strs, s)
	}
	if n, limit := len(JunosValue(strs)), JunosLimit(attr); n > limit {
		return fmt.Sprintf("%s would be %d bytes; the limit is %d (one TACACS+ argument of at most 255 bytes)", JunosArg(attr), n, limit)
	}
	return ""
}
