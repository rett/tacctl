package blocks

// The draft of 'block adopt' for an IOS snmp block (0.2.7): the device's own
// SNMP lines, read live as 'show running-config | include ^snmp-server' and,
// for each access list a community names, 'show running-config | section ip
// access-list standard <NAME>', turned into the text of a block to prune. A
// pure function of text, as AdoptSNMP is.
//
// What a draft holds is only what the grammar of the block takes and what the
// block does not state already:
//
//   - what tacctl renders itself (the structured community and its access
//     list TACCTL-SNMP, the v3 objects) and the device's identity (contact,
//     location, engine id) are never part of a block;
//   - an object (a community by its string, an access list by its name, a host
//     by its address and community, an 'enable traps' statement) that the
//     block in force at the same level states with the same statements, or
//     that the layer beneath states with the same statements, is not
//     repeated; one that is in the same file with other statements is left as
//     it is (the person edits it in place);
//   - what a block cannot hold is left out with a line that says so, never a
//     value: a community with a view or an IPv6 list, one that names a numbered
//     list, a string the device shows as ciphertext, an access list with a
//     deny entry, a log keyword or an entry of another shape.
//
// Nothing here echoes a community string: the notes are counts and the
// shapes of what was left out.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
)

// isDigits reports a word that is a number (a sequence number, a numbered
// access list).
func isDigits(s string) bool { return s != "" && reAllDigits.MatchString(s) }

// AdoptIOSSNMP is the draft of an IOS snmp block from raw, the text of the
// two reads. own is what tacctl renders for the device (its structured
// community string); same is the block in force at the level the draft is
// for and up the block of the layer beneath it (a device's draft: the
// scope's); either may be nil.
func AdoptIOSSNMP(raw string, own AdoptOwn, same, up *IOSSNMPBlock) AdoptResult {
	var res AdoptResult
	var stmts []string // accepted statements, as block text
	var ours, identity, outside int
	var left []string

	type aclRead struct {
		name    string
		entries []string
		bad     bool
	}
	var acls []*aclRead
	var cur *aclRead
	cipher := 0

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "!") {
			continue
		}
		f := strings.Fields(trimmed)
		indented := line != strings.TrimLeft(line, " \t")
		// an entry of the list being read
		if cur != nil && (indented || f[0] == "permit" || f[0] == "deny" || f[0] == "remark" || isDigits(f[0])) {
			if isDigits(f[0]) {
				f = f[1:] // the sequence number
			}
			switch {
			case len(f) == 0 || f[0] == "remark":
			case f[0] != "permit":
				cur.bad = true
			default:
				if _, why := parseACLEntry(f[1:]); why != "" {
					cur.bad = true
				} else {
					cur.entries = append(cur.entries, "permit "+strings.Join(f[1:], " "))
				}
			}
			continue
		}
		cur = nil
		switch {
		case len(f) >= 4 && f[0] == "ip" && f[1] == "access-list" && f[2] == "standard":
			if names.IsTacctlSNMPName(f[3]) {
				ours++
				cur = &aclRead{name: f[3], bad: true} // swallowed
				cur.entries = nil
				continue
			}
			cur = &aclRead{name: f[3]}
			acls = append(acls, cur)
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
			idx := 2
			typed := false
			if len(f) >= 5 && (f[2] == "0" || f[2] == "7" || f[2] == "6") && f[3] != "RO" && f[3] != "RW" && f[3] != "view" && f[3] != "ipv6" {
				idx, typed = 3, f[2] != "0"
			}
			str := f[idx]
			rest := f[idx+1:]
			isOwn := own.Community != "" && str == own.Community && !typed
			for _, w := range f[idx:] {
				if names.IsTacctlSNMPName(w) {
					isOwn = true
				}
			}
			switch {
			case isOwn:
				ours++
				continue
			case typed:
				cipher++
				continue
			}
			access, acl := AccessRO, ""
			bad := ""
			for i := 0; i < len(rest); i++ {
				switch w := rest[i]; {
				case w == "RO" || w == "RW":
					access = w
				case w == "view" || w == "ipv6":
					bad = "names a view or an IPv6 access list"
					i++
				case isDigits(w):
					bad = "names a numbered access list"
				default:
					acl = w
				}
			}
			if bad != "" {
				left = append(left, "a community "+bad+", which a block cannot hold: not adopted")
				continue
			}
			s := "snmp-server community " + str + " " + access
			if acl != "" {
				s += " " + acl
			}
			if _, fs := ParseIOSSNMP(s + "\n"); HasErrors(fs) {
				outside++
				continue
			}
			stmts = append(stmts, s)
		case len(f) >= 4 && f[0] == "snmp-server" && f[1] == "host":
			w := slices.DeleteFunc(slices.Clone(f), func(x string) bool { return x == "traps" })
			if slices.Contains(w, "informs") || slices.Contains(w, "vrf") {
				outside++
				continue
			}
			s := strings.Join(w, " ")
			if _, fs := ParseIOSSNMP(s + "\n"); HasErrors(fs) {
				outside++
				continue
			}
			stmts = append(stmts, s)
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "enable" && f[2] == "traps":
			s := strings.Join(f, " ")
			if _, fs := ParseIOSSNMP(s + "\n"); HasErrors(fs) {
				outside++
				continue
			}
			stmts = append(stmts, s)
		case len(f) >= 2 && f[0] == "snmp-server" && slices.Contains([]string{"contact", "location", "engineID", "chassis-id"}, f[1]):
			identity++
		case len(f) >= 2 && f[0] == "snmp-server" && slices.Contains([]string{"user", "group", "view"}, f[1]):
			isOwn := false
			for _, w := range f {
				if names.IsTacctlSNMPName(w) {
					isOwn = true
				}
			}
			if isOwn {
				ours++
			} else {
				outside++
			}
		case len(f) >= 1 && f[0] == "snmp-server":
			outside++
		}
	}
	for _, a := range acls {
		if a.bad || len(a.entries) == 0 {
			left = append(left, "an access list has an entry a block cannot hold (a deny, a log keyword or another shape) or none: not adopted, a community that names it refers to the device's own list")
			continue
		}
		stmts = append(stmts, "ip access-list standard "+a.name)
		for _, e := range a.entries {
			stmts = append(stmts, " "+e)
		}
	}

	dev, _ := ParseIOSSNMP(strings.Join(stmts, "\n") + "\n")
	incl := &IOSSNMPBlock{}
	var already, conflict int
	unitText := func(b *IOSSNMPBlock) []string { return IOSSNMPStatements(b) }
	for _, c := range dev.Communities {
		st := unitText(&IOSSNMPBlock{Communities: []*IOSCommunity{c}})
		switch {
		case same.community(c.String) != nil:
			if sameSet(st, unitText(&IOSSNMPBlock{Communities: []*IOSCommunity{same.community(c.String)}})) {
				already++
			} else {
				conflict++
			}
		case up.community(c.String) != nil && sameSet(st, unitText(&IOSSNMPBlock{Communities: []*IOSCommunity{up.community(c.String)}})):
			already++
		default:
			incl.Communities = append(incl.Communities, c)
		}
	}
	for _, a := range dev.ACLs {
		st := unitText(&IOSSNMPBlock{ACLs: []*IOSACL{a}})
		switch {
		case same.ACL(a.Name) != nil:
			if sameSet(st, unitText(&IOSSNMPBlock{ACLs: []*IOSACL{same.ACL(a.Name)}})) {
				already++
			} else {
				conflict++
			}
		case up.ACL(a.Name) != nil && sameSet(st, unitText(&IOSSNMPBlock{ACLs: []*IOSACL{up.ACL(a.Name)}})):
			already++
		default:
			incl.ACLs = append(incl.ACLs, a)
		}
	}
	for _, h := range dev.Hosts {
		st := unitText(&IOSSNMPBlock{Hosts: []*IOSHost{h}})
		switch {
		case same.host(h.key()) != nil:
			if sameSet(st, unitText(&IOSSNMPBlock{Hosts: []*IOSHost{same.host(h.key())}})) {
				already++
			} else {
				conflict++
			}
		case up.host(h.key()) != nil && sameSet(st, unitText(&IOSSNMPBlock{Hosts: []*IOSHost{up.host(h.key())}})):
			already++
		default:
			incl.Hosts = append(incl.Hosts, h)
		}
	}
	for _, t := range dev.Traps {
		if same.traps(t.key()) != nil || up.traps(t.key()) != nil {
			already++
			continue
		}
		incl.Traps = append(incl.Traps, t)
	}
	res.Text = incl.String(false)
	res.Statements = len(IOSSNMPUnits(incl))
	res.Objects = res.Statements

	note := func(n int, label, noun, nouns, tail string) {
		if n > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %d %s, %s", label, n, count(n, noun, nouns), tail))
		}
	}
	note(ours, "tacctl's own, rendered from its settings (the scope's community and its access list, v3)", "statement", "statements", "not adopted")
	note(identity, "identity (contact, location, engine id), never part of a block", "statement", "statements", "not adopted")
	note(outside, "outside what an snmp block takes (v3 users and views, queue length, and the like)", "statement", "statements", "not adopted")
	note(already, "stated already, with the same statements, by this block or the scope's", "object", "objects", "not repeated")
	note(conflict, "in this block already with other statements", "object", "objects", "left as they are (edit them in place)")
	if cipher > 0 {
		res.Left = append(res.Left, strconv.Itoa(cipher)+" "+count(cipher, "community is", "communities are")+
			" shown only as the device's ciphertext, so the string cannot be adopted")
	}
	res.Left = append(res.Left, left...)
	return res
}
