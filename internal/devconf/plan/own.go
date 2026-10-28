package plan

// The device's own statements in the report. An extra statement that the
// comparison calls unmanaged (devconf.DiffLine.Unmanaged: another SNMP
// community, a trap group, the SNMP name, a syslog host the system block does
// not name, ...) is not an irregularity: the section reads ok, the plan keeps
// the statement by rule, and 'device config list' shows 'snmp +N unmanaged'.
// The report therefore has no item for it. It says how many there are, per
// section, in one line, and that number is the comparison's own
// (SectionResult.Unmanaged), so the two outputs cannot disagree.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// ownKindsShown is the number of kinds a report line names before it says
// there are more.
const ownKindsShown = 5

// setOwn records the section's unmanaged statements: their number, their
// kinds, and the extras that stand for them.
func (d *Delta) setOwn(name string, r devconf.SectionResult) {
	if r.Unmanaged == 0 {
		return
	}
	o := Own{Section: name, Count: r.Unmanaged}
	for _, l := range r.Lines {
		if l.Op != devconf.OpExtra || !l.Unmanaged {
			continue
		}
		stem := stemOf(l)
		if k := ownKind(d.Vendor, name, stem); k != "" && !slices.Contains(o.Kinds, k) {
			o.Kinds = append(o.Kinds, k)
		}
		for i := range d.Extras {
			if d.Extras[i].Section == name && d.Extras[i].Text == stem {
				d.Extras[i].Own = true
			}
		}
	}
	d.Own = append(d.Own, o)
}

// ownKind names the kind of a statement of the device's own, in the words
// of the report (never a value, a name or a label).
func ownKind(vendor, section, stem string) string {
	switch vendor {
	case devconf.FamilyJunos:
		t := splitTokens(strings.TrimPrefix(stem, "set "))
		if len(t) < 2 {
			return strings.Join(t, " ")
		}
		switch t[0] {
		case "snmp":
			if k, ok := map[string]string{"community": "communities", "trap-group": "trap groups", "trap-options": "trap options",
				"client-list": "client lists", "v3": "SNMPv3 objects", "view": "views", "name": "name", "location": "location",
				"contact": "contact", "description": "description", "engine-id": "engine id", "interface": "interfaces",
				"routing-instance-access": "routing instances"}[t[1]]; ok {
				return k
			}
			return t[1]
		case "system":
			switch {
			case t[1] == "login" && len(t) > 2 && (t[2] == "message" || t[2] == "announcement"):
				return "login messages"
			case t[1] == "login":
				return "login options"
			case t[1] == "services":
				return "NETCONF service"
			}
			if k, ok := map[string]string{"syslog": "syslog", "ntp": "NTP", "domain-name": "domain name", "domain-search": "search domains",
				"name-server": "name servers", "time-zone": "time zone"}[t[1]]; ok {
				return k
			}
			return t[1]
		}
		return t[0]
	case devconf.FamilyWTI:
		f := strings.Fields(stem)
		switch {
		case len(f) == 0:
			return ""
		case f[0] == "iptables":
			return "IP tables tail"
		case f[0] == "snmp" && len(f) > 1 && f[1] == "trap":
			return "trap settings"
		case f[0] == "snmp" && len(f) > 1:
			return strings.ReplaceAll(f[1], "-", " ")
		case f[0] == "radius" || f[0] == "tacacs":
			return map[string]string{"radius": "RADIUS", "tacacs": "TACACS+"}[f[0]] + " settings"
		}
		return f[0]
	}
	path := strings.Split(stem, pathSep)
	f := strings.Fields(path[len(path)-1])
	if len(path) > 1 {
		f = strings.Fields(path[0])
	}
	if len(f) == 0 {
		return ""
	}
	switch f[0] {
	case "snmp-server":
		if len(f) < 2 {
			return "SNMP"
		}
		if k, ok := map[string]string{"community": "communities", "host": "trap hosts", "enable": "trap types", "trap-source": "trap source",
			"location": "location", "contact": "contact", "view": "views", "group": "SNMPv3 groups", "user": "SNMPv3 users",
			"engineID": "engine id"}[f[1]]; ok {
			return k
		}
		return f[1]
	case "ip":
		if len(f) > 1 {
			switch f[1] {
			case "access-list":
				return "access lists"
			case "ssh":
				return "ssh"
			case "name-server":
				return "name servers"
			case "domain", "domain-name", "domain-list":
				return "domain names"
			}
		}
	case "banner":
		return "banners"
	case "logging":
		return "logging"
	case "service":
		return "timestamps"
	case "login", "security":
		return "login policy"
	case "clock":
		return "clock"
	case "ntp":
		return "NTP"
	}
	return f[0]
}

// ownLine is the report line of one section's statements of the device's own.
func ownLine(o Own) string {
	kinds := o.Kinds
	more := ""
	if len(kinds) > ownKindsShown {
		kinds, more = kinds[:ownKindsShown], ", ..."
	}
	what := plural(o.Count, "statement", "statements") + " of the device's own"
	if len(kinds) > 0 {
		what += " (" + strings.Join(kinds, ", ") + more + ")"
	}
	return "Kept: " + o.Section + " " + what + ": left alone, listed by device config diff."
}

// ownExtras is the number of extras that are the device's own.
func (d Delta) ownExtras() int {
	n := 0
	for _, e := range d.Extras {
		if e.Own {
			n++
		}
	}
	return n
}

// addKinds adds kinds of present secrets, each once.
func (c *Counts) addKinds(kinds ...string) {
	for _, k := range kinds {
		if k != "" && !slices.Contains(c.PresentKinds, k) {
			c.PresentKinds = append(c.PresentKinds, k)
		}
	}
}

// secretWhat names what a secret statement is, in the words of the report:
// the kind, never the value, the name of a community or a label.
func secretWhat(vendor, stem string) string {
	switch vendor {
	case devconf.FamilyJunos:
		t := splitTokens(strings.TrimPrefix(stem, "set "))
		switch {
		case len(t) >= 2 && t[0] == "system" && t[1] == "tacplus-server":
			return "the TACACS+ server key"
		case len(t) >= 2 && t[0] == "system" && t[1] == "radius-server":
			return "the RADIUS server key"
		case len(t) >= 2 && t[0] == "snmp" && t[1] == "community":
			return "the SNMP community"
		case len(t) >= 3 && t[0] == "system" && t[1] == "ntp":
			return "an NTP key"
		case len(t) >= 3 && t[0] == "system" && t[1] == "login" && t[2] == "user":
			return "a local account's password"
		}
	case devconf.FamilyWTI:
		f := strings.Fields(stem)
		if len(f) > 0 {
			switch f[0] {
			case "tacacs":
				return "the TACACS+ server key"
			case "radius":
				return "the RADIUS server key"
			case "snmp":
				return "the SNMP community"
			case "user":
				return "a local account's credentials"
			}
		}
	default:
		s := strings.ReplaceAll(stem, pathSep, " ")
		switch {
		case strings.HasPrefix(s, "snmp-server "):
			// a community, or the community a trap host is sent with
			return "the SNMP community"
		case strings.HasPrefix(s, "tacacs") && strings.Contains(s, " key"):
			return "the TACACS+ server key"
		case strings.HasPrefix(s, "radius") && strings.Contains(s, " key"):
			return "the RADIUS server key"
		case strings.HasPrefix(s, "ntp "):
			return "an NTP key"
		case strings.HasPrefix(s, "username "):
			return "a local account's password"
		case strings.HasPrefix(s, "enable "):
			return "the enable secret"
		}
	}
	return "another secret"
}

// secretsLine is the report's one line about secrets: which kinds are
// present (only their presence is compared), and those the pull's login could
// not read (the plan could not check them). "" when there are none.
func secretsLine(c Counts) string {
	var parts []string
	if c.SecretsPresent > 0 {
		kinds := c.PresentKinds
		more := ""
		if len(kinds) > ownKindsShown {
			kinds, more = kinds[:ownKindsShown], ", ..."
		}
		what := fmt.Sprintf("%d present", c.SecretsPresent)
		if len(kinds) > 0 {
			what += " (" + strings.Join(kinds, ", ") + more + ")"
		}
		parts = append(parts, what+"; only their presence is checked, --secrets writes them again.")
	}
	if c.SecretsNotVisible > 0 {
		parts = append(parts, fmt.Sprintf("%d not visible to the pull's login: the plan could not check them (--secrets pushes them).", c.SecretsNotVisible))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Secrets: " + strings.Join(parts, " ")
}
