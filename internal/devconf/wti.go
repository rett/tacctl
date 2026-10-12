package devconf

// WTI console servers (0.2.7). A unit has no configuration listing: the
// extraction reads one document of the unit's captured menu pages (package
// wti), each screen headed '# page: /N > 28', and turns the items the tables
// declare into the canonical statements of wti/canon.go. The comparison is
// the package's own (Compare, with the WTI branches below): a secret by
// presence, an SNMP community by a label against the rendered one, the IP
// tables list in order.
//
// The sections: aaa (the TACACS+ and RADIUS pages), mgmt-acl (the IP tables
// list), snmp (the SNMP access and trap pages) and breakglass (the local
// users of the user directory, when it was read); roles, netconf and system
// have nothing on a unit.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
)

// Notes of a WTI comparison; a report may turn the first two into its
// warnings.
const (
	// NoteWTITail: the list ends with the walkthrough's last step.
	NoteWTITail = "the IP tables list ends with the final DROP and the policies of the walkthrough's last step: kept, not compared"
	// NoteWTINoTail: the list holds no final DROP and no INPUT policy DROP,
	// so it restricts nothing.
	NoteWTINoTail = "the IP tables list has no final DROP and no INPUT policy DROP: it restricts nothing until the last step of the walkthrough is applied"
	// NoteWTIv3: the section of a v3 scope is not compared.
	NoteWTIv3 = "the SNMP v3 users of a unit are not read: this section is not compared"
	// NoteWTIUsersNotRead: the pull did not read the user directory.
	NoteWTIUsersNotRead = "the local users of the unit were not read by this pull: not compared"
)

// wtiTextKeys are the keys whose value is free text, which a menu may print
// truncated.
var wtiTextKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range wti.Pages {
		for _, it := range p.Items {
			if it.Form == wti.FormText && it.Key != "" {
				m[it.Key] = true
			}
		}
	}
	return m
}()

// wtiCommunityNames are the community strings of rendered lines, in order.
func wtiCommunityNames(lines []string) []string {
	var out []string
	for _, l := range lines {
		if c := wti.ParseLine(l); c.Form == wti.FormCommunity && c.Value != "" && !isElided(c.Value) {
			out = append(out, c.Value)
		}
	}
	return out
}

// wtiCommunityLabel is the label of a community string. A string the menu
// printed truncated ('abc...') that is the beginning of exactly one rendered
// string is that string.
func wtiCommunityLabel(name string, lb *labels) string {
	if lb != nil && lb.fresh && len(name) > 3 && strings.HasSuffix(name, "...") {
		prefix := strings.TrimSuffix(name, "...")
		var match string
		n := 0
		for r := range lb.rendered {
			if len(r) > len(prefix) && strings.HasPrefix(r, prefix) {
				match = r
				n++
			}
		}
		if n == 1 {
			name = match
		}
	}
	return lb.of(name)
}

// wtiCanon puts statement lines in the compared form: one statement per
// line, a secret as its presence mark, a community as its label, a text
// quoted when it holds a blank, an IP tables entry as the unit's command.
// marks say which lines of an unknown form hold a secret (the key says it for
// every known one).
func wtiCanon(lines []string, marks []bool, lb *labels) []stmt {
	var out []stmt
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := wti.ParseLine(line)
		secret := false
		switch c.Form {
		case wti.FormUnknown:
			ws := strings.Fields(c.Value)
			if markAt(marks, i) && len(ws) >= 2 {
				ws[len(ws)-1], secret = secretMark, true
			}
			c.Value = strings.Join(ws, " ")
		case wti.FormSecret:
			secret = true
		case wti.FormCommunity:
			if c.Value == "" {
				continue
			}
			c.Value, secret = wtiCommunityLabel(c.Value, lb), true
		case wti.FormUser:
			secret = c.Value == wti.SecretMark
			if c.Value == "" {
				continue
			}
		default:
			if c.Value == "" {
				continue
			}
		}
		x := stmt{secret: secret, path: c.Words()}
		x.stem = c.Raw()
		x.text = x.stem
		out = append(out, x)
	}
	wtiMarkTail(out)
	return out
}

// wtiMarkTail marks the statements of the list's tail: a policy line
// anywhere, and the final DROP and OUTPUT ACCEPT where only tail statements
// come after them. A DROP with a rule after it is no tail: the rule is
// never reached, and the DROP is a difference.
func wtiMarkTail(in []stmt) {
	open := true
	for i := len(in) - 1; i >= 0; i-- {
		x := &in[i]
		if len(x.path) != 2 || x.path[0] != "iptables" {
			continue
		}
		switch v := x.path[1]; {
		case wti.IsPolicy(v):
			x.tail = true
		case wti.IsTailRule(v) && open:
			x.tail = true
		default:
			open = false
		}
	}
}

// wtiExtract is Extract for a WTI unit: the document of its captured pages.
func wtiExtract(raw string, expected []devices.Section, visible *bool) (Extracted, error) {
	doc, err := wti.ParseDocument(cleanText(wti.Clean(raw)))
	if err != nil {
		return Extracted{}, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if v := doc.Version(); v != "" && v != wti.Version {
		return Extracted{}, fmt.Errorf("%w: command menu version %s; the tables were verified for %s", ErrParse, v, wti.Version)
	}
	if miss := doc.Missing(); len(miss) > 0 {
		return Extracted{}, fmt.Errorf("%w: the document lacks the page %s", ErrParse, miss[0])
	}
	var rendered []string
	for _, sec := range expected {
		rendered = append(rendered, sec.Lines...)
	}
	lb := newLabels(FamilyWTI, rendered)
	lb.fresh = true
	by := map[string][]string{}
	for _, st := range doc.Statements() {
		by[st.Section] = append(by[st.Section], st.Raw())
	}
	out := make(map[string]devices.Section, len(SectionNames))
	for _, n := range SectionNames {
		if optionalSection(n) || n == SectionBreakGlass && !doc.UsersRead() {
			continue
		}
		out[n] = toSection(n, uniq(wtiCanon(by[n], nil, lb)))
	}
	vis := true
	if visible != nil {
		vis = *visible
	}
	return Extracted{Vendor: FamilyWTI, Sections: out, SecretsVisible: vis}, nil
}

// wtiIsV3 reports a statement about SNMP v3 users.
func wtiIsV3(x stmt) bool { return strings.HasPrefix(x.stem, "snmp v3") }

// wtiAlign makes the device's statements that stand for a rendered one equal
// to it, with a note: a text the menu printed truncated ('wti.site.exam...')
// that begins as the rendered text, and a default service list that holds
// every service the rendering asks for.
func wtiAlign(exp, dev []stmt) ([]stmt, []string) {
	var notes []string
	out := slices.Clone(dev)
	note := func(s string) {
		if !slices.Contains(notes, s) {
			notes = append(notes, s)
		}
	}
	for i, x := range out {
		if len(x.path) != 2 {
			continue
		}
		key, val := x.path[0], x.path[1]
		switch {
		case wtiTextKeys[key] && len(val) > 3 && strings.HasSuffix(val, "..."):
			prefix := strings.TrimSuffix(val, "...")
			for _, e := range exp {
				if len(e.path) == 2 && e.path[0] == key && len(e.path[1]) > len(prefix) && strings.HasPrefix(e.path[1], prefix) {
					out[i] = e
					note(key + ": the unit shows a truncated value; it begins as the rendered one does, so it is taken as equal")
					break
				}
			}
		case key == "tacacs default-services" || key == "radius default-services":
			have := strings.Split(val, ",")
			for _, e := range exp {
				if len(e.path) != 2 || e.path[0] != key || e.path[1] == val {
					continue
				}
				want := strings.Split(e.path[1], ",")
				if !subset(want, have) {
					continue
				}
				var more []string
				for _, h := range have {
					if !slices.Contains(want, h) {
						more = append(more, h)
					}
				}
				out[i] = e
				note(key + ": the unit allows more services than the standard asks for (" + strings.Join(more, ", ") + "): kept, not compared")
				break
			}
		}
	}
	return out, notes
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// wtiProtocols returns the protocol the rendering is for (tacacs or radius;
// "" when it has none or both) and, when the other one's page holds
// 'enable off' on the device, that other protocol: its whole page is the
// device's own.
func wtiProtocols(exp, dev []stmt) (own string, inactive map[string]bool) {
	has := map[string]bool{}
	for _, x := range exp {
		if len(x.path) > 0 {
			if w, _, _ := strings.Cut(x.path[0], " "); w == "tacacs" || w == "radius" {
				has[w] = true
			}
		}
	}
	switch {
	case has["tacacs"] && !has["radius"]:
		own = "tacacs"
	case has["radius"] && !has["tacacs"]:
		own = "radius"
	default:
		return "", nil
	}
	other := "radius"
	if own == "radius" {
		other = "tacacs"
	}
	for _, x := range dev {
		if len(x.path) == 2 && x.path[0] == other+" enable" && x.path[1] == "off" {
			return own, map[string]bool{other: true}
		}
	}
	return own, nil
}

// wtiKept reports a statement of the device's own by its position or its
// kind: the IP tables list's tail.
func wtiKept(section string, x stmt, _ *renderedSet) bool {
	return section == SectionMgmtACL && x.tail
}

// wtiTailNotes are the notes about the tail of the device's IP tables list.
func wtiTailNotes(dev []stmt) []string {
	var any, tail, drop bool
	for _, x := range dev {
		if len(x.path) != 2 || x.path[0] != "iptables" {
			continue
		}
		any = true
		tail = tail || x.tail
		drop = drop || x.path[1] == "-A INPUT -j DROP" || x.path[1] == "-P INPUT DROP"
	}
	var out []string
	if tail {
		out = append(out, NoteWTITail)
	}
	if any && !drop {
		out = append(out, NoteWTINoTail)
	}
	return out
}

// The statements of the device's own, as shapes: the first words of a
// statement ('$' is an object's number). Each is kept only where the
// rendering says nothing of the same object. A protocol's page is kept
// whole while the rendering is for the other protocol and the device has it
// off; the page items the walkthrough leaves alone (the RADIUS session
// module type, the one-time authentication, the message authenticator, the
// secondary secret and the default access page) are kept for the
// rendering's own protocol.
var wtiShapes = func() []keptShape {
	ownRadius := func(name string, prefix []string, exp *renderedSet) bool {
		return notRendered(name, prefix, exp) && (exp.wtiProto == "radius" || exp.wtiInactive["radius"])
	}
	inactive := func(_ string, prefix []string, exp *renderedSet) bool { return exp.wtiInactive[prefix[0]] }
	never := func(string, []string, *renderedSet) bool { return false }
	return []keptShape{
		{Row: "wti.snmp.system-name", Pattern: "snmp system-name", keep: notRendered},
		{Row: "wti.snmp.contact", Pattern: "snmp contact", keep: notRendered},
		{Row: "wti.snmp.location", Pattern: "snmp location", keep: notRendered},
		{Row: "wti.snmp.trap-manager", Pattern: "snmp trap manager $", keep: notRendered},
		{Row: "wti.snmp.trap-community", Pattern: "snmp trap community", keep: notRendered},
		{Row: "wti.snmp.trap-version", Pattern: "snmp trap version", keep: notRendered},
		{Row: "wti.snmp.trap-engine-id", Pattern: "snmp trap engine-id", keep: notRendered},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius secondary-secret", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius onetime-timer", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius onetime-type", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius session-module", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius message-authenticator", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius default-level", keep: ownRadius},
		{Row: "wti.aaa.radius-unrendered", Pattern: "radius default-services", keep: ownRadius},
		{Row: "wti.aaa.inactive-protocol", Pattern: "tacacs", keep: inactive},
		{Row: "wti.aaa.inactive-protocol", Pattern: "radius", keep: inactive},
		// the tail is decided by position (wtiKept), any other entry is not
		// kept
		{Row: "wti.mgmt-acl.list", Pattern: "iptables", keep: never},
	}
}()

// WTISeverity classifies a finding of a WTI comparison (design W10): the
// AAA and the management list ACCESS, except a protocol's session module and
// debug (COSMETIC); SNMP MONITORING, except the system name, contact and
// location (COSMETIC); the local users ACCESS. The words are those of the
// planner's severities.
func WTISeverity(section, stem string) string {
	w := strings.Fields(stem)
	switch section {
	case SectionAAA:
		if len(w) >= 2 && (w[1] == "session-module" || w[1] == "debug") {
			return "COSMETIC"
		}
		return "ACCESS"
	case SectionMgmtACL, SectionBreakGlass:
		return "ACCESS"
	case SectionSNMP:
		if len(w) >= 2 && (w[1] == "contact" || w[1] == "location" || w[1] == "system-name") {
			return "COSMETIC"
		}
		return "MONITORING"
	}
	return "COSMETIC"
}
