package names

import "strconv"

// The most characters of an SNMP community, v3 user and passphrase that
// every device the walkthroughs address takes (IOS limits a community to 32
// characters; a passphrase is at most 64 here).
const (
	SNMPCommunityMax  = 32
	SNMPPassphraseMax = 64
	SNMPUserMax       = 32
)

// SNMPTokenProblem is why s cannot be written into a device CLI line as an
// SNMP community, v3 user or passphrase ("" when it can): it is printable
// ASCII without blanks (a blank ends the word on Cisco and Junos), without
// '?' (the CLI answers with help instead of taking the character) and
// without '"' (Junos quotes the value; Cisco keeps it as part of the word),
// and at most max characters.
func SNMPTokenProblem(s string, max int) string {
	if len(s) > max {
		return "is longer than " + strconv.Itoa(max) + " characters"
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' || c == '\t':
			return "holds a blank (a device CLI ends the word there)"
		case c == '?':
			return "holds '?' (a device CLI answers with help instead of taking it)"
		case c == '"':
			return "holds '\"' (a device CLI reads it as a quote)"
		case c < 0x21 || c > 0x7e:
			return "holds a character that is not printable ASCII"
		}
	}
	return ""
}
