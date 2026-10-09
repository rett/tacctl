package conf

// The per-scope SNMP settings of tacctl 0.2.3 in tacctl.yaml (decisions D41
// and D46 of docs/plans/0.2.3-plan.md): snmp_scope.<scope>.version, .port,
// .timeout, .v3.auth, .v3.priv (the settings 'config snmp' keeps for the
// default), and the scope's .contact and .clients (the allowed SNMP clients,
// IPv4 CIDRs; the tacctl server's own /32 first and the final 0.0.0.0/0
// restrict are rendered by the walkthroughs and never stored). Nothing has
// a default: an absent key is "not set in the scope", and the default
// beneath it (snmp.*) decides. The community and the v3 passphrases are
// never here: StateDir/snmp/<scope>.yaml (internal/snmpcred).

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/py"
)

// SNMPScopePrefix starts every per-scope SNMP key.
const SNMPScopePrefix = "snmp_scope."

// The settings of a scope, as the keys under snmp_scope.<scope> name them.
const (
	SNMPKeyVersion = "version"
	SNMPKeyPort    = "port"
	SNMPKeyTimeout = "timeout"
	SNMPKeyAuth    = "v3.auth"
	SNMPKeyPriv    = "v3.priv"
	SNMPKeyContact = "contact"
	SNMPKeyClients = "clients"
)

// SNMPKeys are the settings of a scope, in the order they are shown.
var SNMPKeys = []string{SNMPKeyVersion, SNMPKeyPort, SNMPKeyTimeout, SNMPKeyAuth, SNMPKeyPriv, SNMPKeyContact, SNMPKeyClients}

// SNMPPath is the tacctl.yaml key of a scope's setting.
func SNMPPath(scope, key string) string { return SNMPScopePrefix + scope + "." + key }

// MaxSNMPText is the longest contact (and device location) in characters.
const MaxSNMPText = 120

// snmpScopeWildcards are the schema's entries for snmp_scope.<scope>.<key>.
func snmpScopeWildcards() []wildcard {
	return []wildcard{
		{SNMPScopePrefix, Rule{Type: TypeEnum, Values: []string{"v2c", "v3"}, Tail: SNMPKeyVersion}},
		{SNMPScopePrefix, Rule{Type: TypeInt, Min: intp(1), Max: intp(65535), Tail: SNMPKeyPort}},
		{SNMPScopePrefix, Rule{Type: TypeInt, Min: intp(1), Max: intp(10), Tail: SNMPKeyTimeout}},
		{SNMPScopePrefix, Rule{Type: TypeEnum, Values: []string{"sha", "sha256"}, Tail: SNMPKeyAuth}},
		{SNMPScopePrefix, Rule{Type: TypeEnum, Values: []string{"aes128"}, Tail: SNMPKeyPriv}},
		{SNMPScopePrefix, Rule{Type: TypeSNMPText, Tail: SNMPKeyContact}},
		{SNMPScopePrefix, Rule{Type: TypeSNMPClients, Default: []any{}, HasDefault: true, Tail: SNMPKeyClients}},
	}
}

// SNMPTextProblem is why s cannot be a contact or a device location (""
// when it can): 1 to 120 characters of valid UTF-8, no control character,
// no '?' (a device CLI reads a pasted '?' as a request for help).
func SNMPTextProblem(s string) string {
	switch {
	case s == "" || strings.TrimSpace(s) == "":
		return "must not be empty"
	case !utf8.ValidString(s):
		return "must be valid UTF-8"
	case utf8.RuneCountInString(s) > MaxSNMPText:
		return fmt.Sprintf("is limited to %d characters", MaxSNMPText)
	case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "may not contain control characters"
	case strings.Contains(s, "?"):
		return "may not contain '?' (a device CLI treats it as a request for help)"
	}
	return ""
}

func snmpTextProblem(value any) string {
	s, ok := value.(string)
	if !ok {
		return "must be a string"
	}
	return SNMPTextProblem(s)
}

// SNMPClientsProblem is why list cannot be a scope's stored client list
// (""): every entry an IPv4 CIDR in its canonical form that is not
// 0.0.0.0/0, none twice, and no more than cidr.MaxSNMPClients.
func SNMPClientsProblem(list []string) string {
	if len(list) > cidr.MaxSNMPClients {
		return fmt.Sprintf("holds %d entries; at most %d", len(list), cidr.MaxSNMPClients)
	}
	for i, c := range list {
		if why := cidr.ClientProblem(c); why != "" {
			return fmt.Sprintf("element %d: %s %s", i, py.ReprString(c), why)
		}
		for _, prev := range list[:i] {
			if prev == c {
				return fmt.Sprintf("element %d: %s is listed twice", i, py.ReprString(c))
			}
		}
	}
	return ""
}

func snmpClientsProblem(value any) string {
	items, isList := py.List(value)
	if !isList {
		return "must be a list of IPv4 CIDRs"
	}
	list := make([]string, len(items))
	for i, it := range items {
		s, ok := it.(string)
		if !ok {
			return fmt.Sprintf("element %d: must be a string", i)
		}
		list[i] = s
	}
	return SNMPClientsProblem(list)
}
