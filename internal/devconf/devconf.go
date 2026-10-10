// Package devconf reads a device's configuration text and compares the
// sections tacctl manages with what tacctl would render for that device
// (docs/plans/0.2.4-plan.md D61, D62, D64, D65, D66).
//
// The package is pure: no terminal, no network, no wall-clock reads (times
// are passed in), no global state. It does five things:
//
//   - Reader says which commands read a vendor's configuration (D61);
//   - Extract turns that text into the six managed sections (D62): Junos
//     'show configuration | display set' and IOS/IOS-XE 'show
//     running-config';
//   - Normalise and Compare put an extracted section and a rendered one
//     (devices.Section, from devices.Managed) into one form and compare
//     them line by line, a secret by presence only (D64): a Compare result
//     never carries a secret's value;
//   - Store keeps the per-device record and the extracted sections under
//     /var/lib/tacctl (D65), rebuildable and never snapshotted;
//   - Stale says whether a record is out of date against today's rendering
//     (D66).
//
// A statement is one line. Junos: the 'set' line as 'display set' prints it,
// bracket lists and brace blocks expanded, quotes canonical. IOS: the
// submode's lines joined to their context with " > " ('tacacs server TACACS
// > address ipv4 192.0.2.10'), VTY line ranges merged, comments, 'exit' and
// ACL remarks dropped.
package devconf

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/devices"
)

// The six managed sections, in the order devices.Managed returns them.
const (
	SectionAAA        = "aaa"
	SectionRoles      = "roles"
	SectionMgmtACL    = "mgmt-acl"
	SectionSNMP       = "snmp"
	SectionNetconf    = "netconf"
	SectionBreakGlass = "breakglass"
)

// SectionNames are the managed sections, in order.
var SectionNames = []string{SectionAAA, SectionRoles, SectionMgmtACL, SectionSNMP, SectionNetconf, SectionBreakGlass}

// The vendor families the package reads. The registry's vendor words
// (juniper, cisco) and the transport-level names (junos, ios, ios-xe) are
// accepted and map to one of them.
const (
	FamilyJunos = "junos"
	FamilyIOS   = "ios"
)

var (
	// ErrUnsupportedVendor is returned for a vendor with no reader or
	// extractor (wti today).
	ErrUnsupportedVendor = errors.New("devconf: no configuration reader for this vendor")
	// ErrParse is returned by Extract when the text is not a configuration
	// of the vendor: the device refused the command, or the output is
	// something else. It is the pull's 'parse-failed' result.
	ErrParse = errors.New("devconf: the output is not a configuration of this vendor")
)

// Family maps a vendor word to the family the package reads it as.
func Family(vendor string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "junos", "juniper":
		return FamilyJunos, nil
	case "ios", "ios-xe", "iosxe", "cisco":
		return FamilyIOS, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedVendor, vendor)
}

// secretMark stands for a secret's value in a statement that continues
// after it (a Junos community's name, a Cisco key followed by options); a
// value that ends the statement is simply left off.
const secretMark = "<secret>"

// stmt is one canonical statement.
type stmt struct {
	// text is the statement as the device prints it, a secret's value
	// included.
	text string
	// stem is what is compared and shown: text, or for a secret the text
	// with its value elided.
	stem   string
	secret bool
	// path is the statement's parts: Junos tokens after set, IOS the
	// submode context then the line.
	path []string
}

// canonFunc turns lines (and the expected side's secret marks, nil for the
// device's) into canonical statements.
type canonFunc func(lines []string, marks []bool) []stmt

func canonFor(family string) canonFunc {
	if family == FamilyJunos {
		return junosCanon
	}
	return ciscoCanon
}

// uniq drops a repeated statement, by its compared form; statements that
// carry a secret are kept as they come, because the device may hold several
// with the same elided form (two communities with the same options) and
// they are compared as a multiset.
func uniq(in []stmt) []stmt {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !s.secret {
			if seen[s.stem] {
				continue
			}
			seen[s.stem] = true
		}
		out = append(out, s)
	}
	return out
}

// cleanText makes a device's output one statement per line: line ends
// unified, escape sequences, backspaces and control characters removed,
// invalid UTF-8 replaced, pager remnants dropped.
func cleanText(raw string) string {
	raw = strings.ToValidUTF8(raw, "�")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	buf := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == 0x1b: // ESC [ ... final byte (CSI), or ESC and one character
			i++
			if i < len(raw) && raw[i] == '[' {
				i++
				for i < len(raw) && (raw[i] < 0x40 || raw[i] > 0x7e) {
					i++
				}
			}
			if i < len(raw) {
				i++
			}
		case c == '\b':
			// backspace: the paged "--More--" remnants erase themselves
			if n := len(buf); n > 0 {
				_, size := utf8.DecodeLastRune(buf)
				buf = buf[:n-size]
			}
			i++
		case c == '\t':
			buf = append(buf, ' ')
			i++
		case c < 0x20 && c != '\n':
			i++
		case c == 0x7f:
			// DEL is no character of a statement (and no YAML reader takes it).
			buf = append(buf, '?')
			i++
		case c >= 0x80:
			// One rune: the ones that are unsafe in a statement (below) are
			// shown as '?', as the CLI shows a device's text.
			r, size := utf8.DecodeRuneInString(raw[i:])
			if unsafeRune(r) {
				buf = append(buf, '?')
			} else {
				buf = append(buf, raw[i:i+size]...)
			}
			i += size
		default:
			buf = append(buf, c)
			i++
		}
	}
	var out []string
	for _, l := range strings.Split(string(buf), "\n") {
		l = strings.TrimRight(l, " ")
		if isPagerLine(l) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// unsafeRune reports a rune that must not be in a statement: the C1 controls
// (U+0080-U+009F, among them NEL, a line break of YAML), the Unicode line and
// paragraph separators, and the two non-characters U+FFFE and U+FFFF. Each
// either splits a statement in two when the sections file is read back or
// makes the file unreadable (the reader rejects it as a special character).
func unsafeRune(r rune) bool {
	return r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0xFFFE || r == 0xFFFF
}

// scrub is s with its unsafe runes and line breaks shown as '?': what the
// sections file may hold of a statement.
func scrub(s string) string {
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) || r == '\n' || r == '\r' || (r < 0x20 && r != '\t') {
			return '?'
		}
		return r
	}, s)
}

// isPagerLine matches what a device's pager leaves in the text.
func isPagerLine(l string) bool {
	t := strings.TrimSpace(l)
	return strings.HasPrefix(t, "---(more") || strings.HasPrefix(t, "--More--") || strings.HasPrefix(t, "<--- More --->")
}

// sectionOf returns the named section of a list, or an empty one.
func sectionOf(secs []devices.Section, name string) devices.Section {
	for _, s := range secs {
		if s.Name == name {
			return s
		}
	}
	return devices.Section{Name: name}
}

// markAt is Secret[i] with a short or nil Secret meaning false.
func markAt(marks []bool, i int) bool { return i < len(marks) && marks[i] }

// toSection builds a devices.Section from statements: Lines are the
// compared form (a secret's value elided), Secret marks the statements that
// carried one. Nothing a device printed as a secret is in it.
func toSection(name string, in []stmt) devices.Section {
	s := devices.Section{Name: name, Lines: make([]string, len(in)), Secret: make([]bool, len(in))}
	for i, x := range in {
		s.Lines[i], s.Secret[i] = x.stem, x.secret
	}
	return s
}
