package devconf

// The source of the AAA client against the device's interfaces (0.2.23,
// D314). A source address that no interface of the device holds, or a source
// interface that does not exist or carries no address may not be used, and
// the AAA packets may not reach the server (they leave from no such address,
// or from the outgoing interface, as the device decides), without a word. The
// leaves of tacctl's own server are the device's own (unmanaged.go), so this
// is the one check that can make one of them a finding.
//
// Scope: the source of the TACACS+ and RADIUS client only. A Junos 'system
// tacplus-server|radius-server <addr> source-address <ip>', an IOS 'ip
// tacacs|radius source-interface <name>' (the device's own, tacctl's, and the
// older form under tacctl's server group). The sources of syslog, NTP and
// SNMP are not checked.
//
// The check needs the addresses the pull recorded (InterfaceFacts), and
// assumes that the pull's login sees every interface: a class that hides only
// some of them cannot be told from one that shows all, so a source on a hidden
// interface reads as one the device does not hold (hence "this login can
// see" in the words). A shut interface (Junos 'disable', IOS 'shutdown')
// still holds its address; operational state is not checked. A record
// without them (pulled before 0.2.23) or whose pull saw no interface (a login
// that cannot see them) has nothing to check against: the source stays the
// device's own, and the section says so in a note.

import (
	"slices"
	"strings"
)

// The words of a source that is not on the device.
const (
	whyNoAddress = "is not an address of any interface this login can see"
	whyNoIface   = "no such interface with an address that this login can see"
)

// The notes of a source that is not checked.
const (
	noteSourceNotRecorded = "the source of the AAA server is not checked against the interfaces of the device: " +
		"their addresses are not recorded (pull the device again)"
	noteSourceNotVisible = "the source of the AAA server is not checked against the interfaces of the device: " +
		"this login cannot see the interfaces"
)

// Source kinds.
const (
	sourceAddress   = "address"
	sourceInterface = "interface"
)

// aaaSource reads the words of a statement of the aaa section as the source
// of the AAA client: its kind and the address or interface it names.
func aaaSource(fam string, w []string) (kind, value string, ok bool) {
	switch fam {
	case FamilyJunos:
		if len(w) >= 5 && w[0] == "system" && (w[1] == "tacplus-server" || w[1] == "radius-server") && w[3] == "source-address" {
			return sourceAddress, w[4], true
		}
	case FamilyIOS:
		switch {
		case len(w) >= 4 && w[0] == "ip" && (w[1] == "tacacs" || w[1] == "radius") && w[2] == "source-interface":
			return sourceInterface, w[3], true
		case len(w) >= 9 && w[0] == "aaa" && w[1] == "group" && w[2] == "server" && w[5] == "ip" &&
			(w[6] == "tacacs" || w[6] == "radius") && w[7] == "source-interface":
			return sourceInterface, w[8], true
		}
	}
	return "", "", false
}

// checkable reports whether the facts can tell a source from a wrong one.
func (f *InterfaceFacts) checkable() bool { return f != nil && f.Visible }

// sourceNote is the note of a source that cannot be checked.
func (f *InterfaceFacts) sourceNote() string {
	if f == nil {
		return noteSourceNotRecorded
	}
	return noteSourceNotVisible
}

// problem says what is wrong with a source: "" when the device holds it, and
// when the facts cannot tell (nothing recorded, an address the device takes
// by itself, a value that is no address). The addresses compare as parsed
// addresses, not as text.
func (f *InterfaceFacts) problem(kind, value string) string {
	if !f.checkable() {
		return ""
	}
	if kind == sourceInterface {
		if len(f.Addresses[strings.ToLower(value)]) == 0 {
			return "source-interface " + value + ": " + whyNoIface
		}
		return ""
	}
	want, ok := canonAddr(value)
	if !ok {
		return ""
	}
	for _, as := range f.Addresses {
		if slices.Contains(as, want) || slices.Contains(as, dynamicAddress) {
			return ""
		}
	}
	return "source-address " + value + " " + whyNoAddress
}

// sourceCheck is the check of one section's comparison: what it found.
type sourceCheck struct {
	fam   string
	facts *InterfaceFacts
	// unchecked is set when a source was found that the facts could not
	// check.
	unchecked bool
}

// why checks a statement of the aaa section that is the device's own (or
// that the rendering states): "" when it is no source, is the device's, or
// cannot be checked (then unchecked is set for the note).
func (c *sourceCheck) why(x stmt) string {
	kind, value, ok := aaaSource(c.fam, stmtWords(c.fam, x))
	if !ok {
		return ""
	}
	if !c.facts.checkable() {
		c.unchecked = true
		return ""
	}
	return c.facts.problem(kind, value)
}

// iosProtocolRendered reports whether the rendering of the aaa section has a
// server or a server group of the protocol ("tacacs" or "radius").
func iosProtocolRendered(exp []stmt, proto string) bool {
	group := "aaa group server " + proto
	if proto == "tacacs" {
		group = "aaa group server tacacs+"
	}
	return slices.ContainsFunc(exp, func(x stmt) bool {
		return len(x.path) > 0 && (strings.HasPrefix(x.path[0], proto+" server ") ||
			strings.HasPrefix(x.path[0], proto+"-server ") || strings.HasPrefix(x.path[0], group+" "))
	})
}

// iosGroupHasSource reports whether a server group of the rendering (tacctl's
// own) holds a source interface of the protocol, in the rendering or on the
// device.
func iosGroupHasSource(exp, dev []stmt, proto string) bool {
	group := "aaa group server " + proto + " "
	if proto == "tacacs" {
		group = "aaa group server tacacs+ "
	}
	own := map[string]bool{}
	for _, x := range exp {
		if len(x.path) > 0 && strings.HasPrefix(x.path[0], group) {
			own[x.path[0]] = true
		}
	}
	cmd := "ip " + proto + " source-interface "
	return slices.ContainsFunc(slices.Concat(exp, dev), func(x stmt) bool {
		return len(x.path) == 2 && own[x.path[0]] && strings.HasPrefix(x.path[1], cmd)
	})
}

// iosGlobalSources are the device's own 'ip tacacs|radius source-interface'
// statements that the extraction leaves out of the section (the rendering
// sets none of that protocol) and that matter to the AAA the rendering sets
// up: the pull recorded them in the facts. Those the facts say are wrong are
// returned as statements to be compared like the section's own extras; the
// others are counted in c.unchecked when they cannot be checked.
func (c *sourceCheck) iosGlobalSources(exp, dev []stmt) (out []stmt, bad map[string]string) {
	if c.fam != FamilyIOS || c.facts == nil || len(c.facts.Sources) == 0 {
		return nil, nil
	}
	for _, proto := range []string{"tacacs", "radius"} {
		v := c.facts.Sources[proto]
		if v == "" || !iosProtocolRendered(exp, proto) {
			continue
		}
		cmd := "ip " + proto + " source-interface"
		if iosGroupHasSource(exp, dev, proto) {
			// tacctl's server group names its own source interface, which
			// overrides the global one for the login path the method lists
			// name: the global one is not what the requests use
			continue
		}
		if slices.ContainsFunc(exp, func(x stmt) bool { return len(x.path) == 1 && strings.HasPrefix(x.path[0], cmd+" ") }) {
			// the rendering sets one: the section holds the device's
			continue
		}
		x := stmt{text: cmd + " " + v, stem: cmd + " " + v, path: []string{cmd + " " + v}}
		if !c.facts.checkable() {
			c.unchecked = true
			continue
		}
		if w := c.facts.problem(sourceInterface, v); w != "" {
			if bad == nil {
				bad = map[string]string{}
			}
			bad[x.stem] = w
			out = append(out, x)
		}
	}
	return out, bad
}
