package plan

// The old server forms at the standard's address (D117, amended after a plan
// run on a real 15.6 device).
//
// IOS silently refuses a second server entry with the same address and key.
// A device that already holds the standard's server under another form (the
// legacy 'tacacs-server host <A> ...' line on a modern image, or a named
// 'tacacs server <OTHER>' block with address <A>, the shape every earlier
// walkthrough produced) therefore cannot take the standard block beside it,
// and a group that names the standard block by 'server name' would name a
// block that does not exist. The region replaces the old form instead, in
// this order:
//
//	(a) the command-authorization lists that name an affected group are taken
//	    off, typed while the server still answers (the pasting session is a
//	    TACACS+ user: with no list a command is not authorized);
//	(b) the group entries that name the old form, then the old block or host
//	    line;
//	(c) the standard block, the group's 'server name' and the rest of D118's
//	    order;
//	(d) the lists of (a) typed again, last, as D118 orders command
//	    authorization.
//
// The back-out is the inverse of that sequence. The by-hand steps of D117
// remain for the one case the plan cannot prove: a device that authorizes
// commands and shows no server in use (a pasting session that may not be a
// TACACS+ user).

import (
	"slices"
	"strconv"
	"strings"
)

// oldForm is one server entry of the device at the address the plan types
// the standard block's address and key for.
type oldForm struct {
	// proto is "tacacs" or "radius".
	proto string
	// header is the named block's header ('tacacs server OTHER'); "" for a
	// host line.
	header string
	// host is the words of a legacy host line.
	host []string
	// addr is the server's address.
	addr string
	// stems are the device statements the form holds: every statement under
	// the block's header, or the host line itself.
	stems []string
	// entries are the group statements that name the form.
	entries []oldEntry
	// stdName is the name of the standard block that replaces the form
	// ('TACACS', 'RADIUS').
	stdName string
}

// oldEntry is a statement of a group that names an old form.
type oldEntry struct {
	// header is the group ('aaa group server tacacs+ G'), leaf the entry
	// ('server name OTHER', 'server 192.0.2.10'), stem the compared statement.
	header, leaf, stem string
}

// removal is the text the form is removed with: 'no <removal>'.
func (f *oldForm) removal() string {
	if f.header != "" {
		return f.header
	}
	return hostEntry(f.host)
}

// legacyHostsToReplace are the device's server entries (a 'tacacs-server host'
// or 'radius-server host' line, or a named block of another name) at the
// address of the standard block the plan types an address or a key for: IOS
// refuses a second entry with the same address and key, so the standard is
// never added beside them (D117). Nothing when the plan types neither (the
// ios12 rendering has no named block for TACACS+, and a block that has its
// address and key needs nothing).
func (p *planner) legacyHostsToReplace(missing []iosEntry) []*oldForm {
	var out []*oldForm
	for _, kind := range []struct{ proto, block, host, group string }{
		{"tacacs", "tacacs server ", "tacacs-server", "aaa group server tacacs+ "},
		{"radius", "radius server ", "radius-server", "aaa group server radius "}} {
		stdHdr, addr := "", ""
		var ports []string
		for _, e := range p.ios.entries["aaa"] {
			if len(e.ctx) == 1 && strings.HasPrefix(e.ctx[0], kind.block) && strings.HasPrefix(e.leaf, "address ipv4 ") {
				// a RADIUS block's leaf goes on with the ports
				if f := strings.Fields(e.leaf); len(f) >= 3 {
					stdHdr, addr, ports = e.ctx[0], f[2], f[3:]
				}
				break
			}
		}
		if addr == "" || !slices.ContainsFunc(missing, func(e iosEntry) bool {
			return len(e.ctx) == 1 && e.ctx[0] == stdHdr &&
				(strings.HasPrefix(e.leaf, "address ipv4 ") || strings.HasPrefix(e.leaf, "key "))
		}) {
			continue
		}
		stdName := strings.TrimPrefix(stdHdr, kind.block)
		byHeader := map[string]*oldForm{}
		var forms []*oldForm
		lines := p.cur.Sections["aaa"].Lines
		for _, s := range lines {
			path := strings.Split(s, pathSep)
			f := strings.Fields(path[len(path)-1])
			switch {
			case len(path) == 1 && len(f) >= 3 && f[0] == kind.host && f[1] == "host" && f[2] == addr && samePorts(f[3:], ports):
				forms = append(forms, &oldForm{proto: kind.proto, host: f, addr: addr, stems: []string{s}, stdName: stdName})
			case len(path) == 2 && strings.HasPrefix(path[0], kind.block) && path[0] != stdHdr &&
				len(f) >= 3 && f[0] == "address" && f[1] == "ipv4" && f[2] == addr && samePorts(f[3:], ports):
				of := &oldForm{proto: kind.proto, header: path[0], addr: addr, stdName: stdName}
				byHeader[path[0]] = of
				forms = append(forms, of)
			}
		}
		for _, of := range forms {
			if of.header == "" {
				continue
			}
			for _, s := range lines {
				if strings.HasPrefix(s, of.header+pathSep) {
					of.stems = append(of.stems, s)
				}
			}
		}
		// the group entries that name them
		for _, s := range lines {
			path := strings.Split(s, pathSep)
			if len(path) != 2 || !strings.HasPrefix(path[0], kind.group) {
				continue
			}
			f := strings.Fields(path[1])
			switch {
			case len(f) == 3 && f[0] == "server" && f[1] == "name":
				if of := byHeader[kind.block+f[2]]; of != nil {
					of.entries = append(of.entries, oldEntry{path[0], path[1], s})
				}
			case len(f) >= 2 && f[0] == "server" && f[1] == addr:
				for _, of := range forms {
					if of.header == "" && samePorts(f[2:], of.host[3:]) {
						of.entries = append(of.entries, oldEntry{path[0], path[1], s})
					}
				}
			}
		}
		out = append(out, forms...)
	}
	return out
}

// samePorts reports whether a legacy RADIUS host entry's words (after the
// address) do not name a port that differs from the block's: IOS keys a
// RADIUS host on its address and ports, so an entry on other ports is another
// server and does not collide with the block.
func samePorts(entry, block []string) bool {
	for _, kw := range []string{"auth-port", "acct-port"} {
		e, b := slices.Index(entry, kw), slices.Index(block, kw)
		if e >= 0 && e+1 < len(entry) && b >= 0 && b+1 < len(block) && entry[e+1] != block[b+1] {
			return false
		}
	}
	return true
}

// affectedCmdLists are the device's command-authorization statements that the
// removal of the old TACACS+ forms would leave unable to authorize: every
// 'aaa authorization commands <level> <list> ...' that names a group holding
// one of the old forms, or 'group tacacs+' (every TACACS+ server); and, when
// any of those exists, 'aaa authorization config-commands'. The statements
// are in the order the device has them; the config-commands statement, which
// is typed first when removing, comes first.
func (p *planner) affectedCmdLists(forms []*oldForm) []string {
	groups := map[string]bool{}
	any := false
	for _, f := range forms {
		if f.proto != "tacacs" {
			continue
		}
		any = true
		for _, e := range f.entries {
			groups[strings.Fields(e.header)[len(strings.Fields(e.header))-1]] = true
		}
	}
	if !any {
		return nil
	}
	var lists []string
	config := ""
	for _, s := range p.cur.Sections["aaa"].Lines {
		f := strings.Fields(s)
		switch {
		case s == "aaa authorization config-commands":
			config = s
		case len(f) >= 5 && f[0] == "aaa" && f[1] == "authorization" && f[2] == "commands" && !strings.Contains(s, pathSep):
			for i := 4; i+1 < len(f); i++ {
				if f[i] == "group" && (groups[f[i+1]] || f[i+1] == "tacacs+") {
					lists = append(lists, s)
					break
				}
			}
		}
	}
	if len(lists) > 0 && config != "" {
		lists = append([]string{config}, lists...)
	}
	return lists
}

// serverInUse reports whether the pulled configuration already uses the
// scope's server through a group: its address is in a server block or a host
// line AND a login or exec method list names a group. A device that shows
// this is one a TACACS+ user has logged in to, so the pasting session is one
// (D117, amended; the command-authorization shortcut of serverProven does not
// count: it is the very hazard).
func (p *planner) serverInUse() bool {
	lines := p.cur.Sections["aaa"].Lines
	addr := ""
	for _, e := range p.ios.entries["aaa"] {
		if len(e.ctx) == 1 && strings.HasPrefix(e.ctx[0], "tacacs server ") && strings.HasPrefix(e.leaf, "address ipv4 ") {
			addr = strings.Fields(e.leaf)[2]
			break
		}
		if f := strings.Fields(e.stem); len(e.ctx) == 0 && len(f) >= 3 && f[0] == "tacacs-server" && f[1] == "host" {
			addr = f[2]
			break
		}
	}
	if addr == "" {
		return false
	}
	known, named := false, false
	for _, s := range lines {
		path := strings.Split(s, pathSep)
		f := strings.Fields(path[len(path)-1])
		switch {
		case len(path) == 1 && len(f) >= 3 && f[0] == "tacacs-server" && f[1] == "host" && f[2] == addr:
			known = true
		case len(path) == 2 && strings.HasPrefix(path[0], "tacacs server ") && len(f) >= 3 && f[0] == "address" && f[2] == addr:
			known = true
		case len(path) == 1 && len(f) >= 5 && f[0] == "aaa" &&
			(f[1] == "authentication" && f[2] == "login" || f[1] == "authorization" && f[2] == "exec"):
			if i := slices.Index(f[4:], "group"); i >= 0 && i+1 < len(f[4:]) {
				named = true
			}
		}
	}
	return known && named
}

// oldFormLines are the lines that replace the old forms in the region: the
// removal of the command-authorization lists, the removal of the group
// entries and the removal of the forms (in this order), and the lines that
// point a group of another name than the standard's at the standard block.
type oldFormLines struct {
	// cmd, entries and forms are the removals (a), (b1) and (b2).
	cmd, entries, forms []Line
	// point types 'server name <std>' in a group the standard does not
	// render, in place of the entry removed there.
	point []Line
}

// buildOldFormLines makes the lines of (a), (b) and the pointing of the other
// groups. planned says which list statements are removed anyway as extras of
// an unrendered level (their removal answers the finding); the caller types
// the others again last, unless the plan types them as missing.
func (p *planner) buildOldFormLines(section string, forms []*oldForm, cmd []string, planned map[string]bool) oldFormLines {
	var out oldFormLines
	for _, s := range cmd {
		l := Line{Op: OpNo, Text: s, Section: section, Undo: []Line{{Op: OpLine, Text: s}}}
		if planned[s] {
			l.For = []string{s}
		}
		out.cmd = append(out.cmd, l)
	}
	pointed := map[string]bool{}
	for _, f := range forms {
		for _, e := range f.entries {
			l := Line{Op: OpNo, Section: section, Context: []string{e.header}, Text: e.leaf, For: []string{e.stem},
				Undo: []Line{{Op: OpLine, Context: []string{e.header}, Text: e.leaf}}}
			out.entries = append(out.entries, l)
			// a group the standard does not render keeps resolving: it gets the
			// standard block in place of the entry (the rendered group has the
			// statement as a missing one)
			if p.ios.kinds[e.header] == nil && !pointed[e.header] {
				pointed[e.header] = true
				leaf := "server name " + f.stdName
				out.point = append(out.point, Line{Op: OpLine, Section: section, Context: []string{e.header}, Text: leaf,
					Undo: []Line{{Op: OpNo, Context: []string{e.header}, Text: leaf}}})
			}
		}
	}
	for _, f := range forms {
		l := Line{Op: OpNo, Text: f.removal(), Section: section, For: slices.Clone(f.stems)}
		if f.header == "" {
			// the line's key is the device's own: the back-out says to type it
			// again, the key to be put in by hand
			l.Undo = []Line{{Op: OpComment, Text: "type again with its original secret: " + shownSecret(f.stems[0])}}
		} else {
			l.Undo = p.blockUndo(f)
		}
		out.forms = append(out.forms, l)
	}
	return out
}

// blockUndo types an old named block again: its header and its leaves as the
// pull showed them, a secret one as a note (the record holds no value).
func (p *planner) blockUndo(f *oldForm) []Line {
	var undo []Line
	for _, s := range f.stems {
		path := strings.Split(s, pathSep)
		leaf := path[len(path)-1]
		if strings.Contains(s, secretMark) || leaf == "key" || strings.HasPrefix(leaf, "key ") {
			undo = append(undo, Line{Op: OpComment, Text: "type again with its original secret: " + shownSecret(s)})
			continue
		}
		undo = append(undo, Line{Op: OpLine, Context: []string{f.header}, Text: leaf})
	}
	if len(undo) == 0 || !slices.ContainsFunc(undo, func(u Line) bool { return u.Op == OpLine }) {
		// a block with no leaf, or only its key: the header is typed so that the
		// block exists for the note to refer to
		undo = append([]Line{{Op: OpLine, Text: f.header}}, undo...)
	}
	return undo
}

// byHandIndent is what a typed line of the by-hand steps is indented by; a
// numbered line of the steps starts at the left.
const byHandIndent = "    "

// byHandStepZero is step 0 of the by-hand steps of a device that also
// authorizes the commands typed on the console (SF2): the setting goes first.
const byHandStepZero = "0. This device authorizes the commands typed on the console ('aaa authorization console'): the four steps cannot be typed with it on " +
	"(after step 1 the group has no server, command authorization falls to 'local' and a TACACS+ user is not in the local database). " +
	"Take it off first, while the TACACS+ user's commands still pass; the standard never sets it and it is not put back. " +
	"If the console session is refused after it, type steps 1 to 4 from a new session as a user that reaches privilege 15:"

// migrationSteps are the steps to type by hand, on the console as any user
// that reaches privilege 15 there, to move a device from the old server entry
// at the standard's address to the standard block (D117), as a short numbered
// list: a numbered line says what the lines under it do, and the lines under
// it (indented) are typed as they stand, in configuration mode. They are given
// outside any region, for the one case the plan cannot prove the pasting
// session is a TACACS+ user: a device that authorizes commands and shows no
// server in use.
//
// DECISION: the device's own groups are kept and pointed at the named
// server, not replaced: the method lists name the group (whatever its name),
// so a group that holds 'server <address>' gets ' server name <block>' and
// loses the address, and every list keeps resolving. A group of another name
// than the standard is the standard's business after the pull (it shows as
// extra, and the standard group and the lists are typed by the plan then).
// The old entry goes first: IOS refuses a second server entry at the same
// address and key, and for the few lines between 1 and 3 the group does not
// resolve, so the command authorization lists fall to their local fallback
// (the console user is local and at privilege 15).
func (p *planner) migrationSteps(forms []*oldForm) []string {
	var removals []string
	for _, f := range forms {
		removals = append(removals, "no "+f.removal())
	}
	slices.Sort(removals)
	t := func(s string) string { return byHandIndent + s }

	// the named block, as the rendering has it
	var blockName string
	var block []string
	for _, e := range p.ios.entries["aaa"] {
		if len(e.ctx) != 1 || !strings.HasPrefix(e.ctx[0], "tacacs server ") {
			continue
		}
		if e.ctx[0] != blockName {
			blockName = e.ctx[0]
			block = append(block, t(blockName))
		}
		leaf := e.leaf
		if strings.HasPrefix(leaf, "key ") {
			scope := p.opt.Scope
			if scope == "" {
				scope = "<scope>"
			}
			leaf = "key <the scope's key: tacctl scope secret show " + scope + ">"
		}
		block = append(block, t(" "+leaf))
	}
	serverName := strings.TrimPrefix(blockName, "tacacs server ")

	// the groups that hold an old entry, in the order the device has them
	var groups []string
	holds := map[string][]string{}
	for _, s := range p.cur.Sections["aaa"].Lines {
		for _, f := range forms {
			for _, e := range f.entries {
				if e.stem != s {
					continue
				}
				if _, ok := holds[e.header]; !ok {
					groups = append(groups, e.header)
				}
				holds[e.header] = append(holds[e.header], e.leaf)
			}
		}
	}
	anyHolds := len(groups) > 0
	if len(groups) == 0 {
		// no group holds the address: the standard group, as the rendering has it
		for _, e := range p.ios.entries["aaa"] {
			if len(e.ctx) == 1 && strings.HasPrefix(e.ctx[0], "aaa group server tacacs+ ") && !slices.Contains(groups, e.ctx[0]) {
				groups = append(groups, e.ctx[0])
			}
		}
	}

	var steps []string
	if slices.ContainsFunc(p.cur.Sections["aaa"].Lines, func(s string) bool {
		return s == "aaa authorization console" || strings.HasPrefix(s, "aaa authorization console ")
	}) {
		// SF2: with the console under command authorization the four steps
		// cannot be typed: after step 1 the group has no server, command
		// authorization falls to 'local', and a TACACS+ user is not in the
		// local database; a local user, for its part, cannot get an exec
		// while the server answers. So the setting goes first, while the
		// TACACS+ user's commands still pass.
		steps = append(steps,
			byHandStepZero,
			t("configure terminal"),
			t("no aaa authorization console"),
			t("end"))
	}
	n := 1
	num := func(s string) { steps = append(steps, strconv.Itoa(n)+". "+s); n++ }
	num("Enter configuration mode and remove the old server entry (the groups that name its address do not resolve until step 3):")
	steps = append(steps, t("configure terminal"))
	for _, h := range removals {
		steps = append(steps, t(h))
	}
	num("Add the named server block (the key is the scope's, shown by the command in the brackets):")
	steps = append(steps, block...)
	steps = append(steps, t("exit"))
	if anyHolds {
		num("Point each group that held the old address at the named block, then drop the address (the method lists keep naming the group):")
	} else {
		lists := "the method lists keep naming what they name"
		if slices.ContainsFunc(p.cur.Sections["aaa"].Lines, func(s string) bool {
			return strings.HasPrefix(s, "aaa ") && strings.Contains(s, " group tacacs+")
		}) {
			lists = "the method lists use 'group tacacs+' and keep using it"
		}
		num("No server group holds the old address, so the standard group is created and pointed at the named block (" + lists + "):")
	}
	for _, g := range groups {
		steps = append(steps, t(g), t(" server name "+serverName))
		for _, a := range holds[g] {
			steps = append(steps, t(" no "+a))
		}
		steps = append(steps, t("exit"))
	}
	num("Leave configuration mode, then open a NEW session as yourself and check 'show privilege' and one command before you pull and plan again:")
	steps = append(steps, t("end"))
	return steps
}
