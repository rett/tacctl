package plan

// The IOS planner (plan §4b, D100, D106).

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

const pathSep = " > "

// LoginLeaf is a line's login method as the device shows it: Line is the
// line header ('line vty 0 4', 'line con 0'), Text the leaf ('login local',
// 'login authentication default', 'no login'). The back-out of 'aaa
// new-model' restores them (D106 (ii)).
type LoginLeaf struct {
	Line string `json:"line"`
	Text string `json:"text"`
}

// The markers WP13.1b's extraction leaves in the aaa section (devconf:
// enableHeld, enableNone): the presence of an 'enable' secret, one of the
// two in every extraction of the current version.
const (
	enableHeldStem = "enable secret " + secretMark
	enableNoneStem = "no enable secret"
)

// LoginLeaves reads the vty and console login leaves out of an extraction
// (WP13.1b, D107): the statements 'line vty <range> > login ...' and 'line
// con 0 > login ...' of its aaa section, as the device printed them, or, with
// 'aaa new-model' on and no leaf on a line, the synthesized 'login
// authentication default' (a merged range is one statement). A device with
// no 'aaa new-model' and no leaf has no method and no leaf is listed.
//
// known is false only for a record by an older tacctl: no leaf and none of
// the enable markers that every current extraction leaves.
func LoginLeaves(ex devconf.Extracted) (leaves []LoginLeaf, known bool) {
	marker := false
	for _, s := range ex.Sections["aaa"].Lines {
		if s == enableHeldStem || s == enableNoneStem {
			marker = true
			continue
		}
		path := strings.Split(s, pathSep)
		if len(path) != 2 || !strings.HasPrefix(path[0], "line vty ") && !strings.HasPrefix(path[0], "line con ") {
			continue
		}
		if strings.HasPrefix(path[1], "login") || path[1] == "no login" {
			leaves = append(leaves, LoginLeaf{Line: path[0], Text: path[1]})
		}
	}
	return leaves, marker || len(leaves) > 0
}

// enableOf reads whether the device has a secret or password for level 15:
// "present", "absent", or "" when the record does not say. It reads the
// marker statement of the extraction and, failing that, the note Compare
// adds when none is held (WP13.1b).
func enableOf(ex devconf.Extracted, notes []string) string {
	for _, s := range ex.Sections["aaa"].Lines {
		switch s {
		case enableHeldStem:
			return "present"
		case enableNoneStem:
			return "absent"
		}
	}
	for _, n := range notes {
		if strings.HasPrefix(n, "no enable secret on the device") {
			return "absent"
		}
	}
	return ""
}

// iosEntry is one rendered statement with the raw text a person types.
type iosEntry struct {
	stem   string
	ctx    []string
	leaf   string
	secret bool
	// noRaw is set for an entry rebuilt from its compared stem: the
	// rendering's own text was not found, so a secret has no value.
	noRaw bool
}

func (e iosEntry) path() []string { return strings.Split(e.stem, pathSep) }

type iosState struct {
	// entries per section, in rendered order; byStem queues per section.
	entries map[string][]iosEntry
	byStem  map[string]map[string][]int
	used    map[string]map[int]bool
	// login leaves and enable secret, from the record.
	login      []LoginLeaf
	loginKnown bool
	enable     string
	// renderedKeys are the supersession keys of every rendered statement.
	renderedKeys map[string]bool
	// kinds are, per rendered context header, the leaf keywords rendered.
	kinds map[string]map[string]bool
	// levels are the privilege levels rendered.
	levels map[string]bool
	// aclHeaders are the rendered ACL headers per section.
	acls map[string]bool
	// real maps the label of a rendered community string ('<secret:2>') to
	// the string, for the lines of the back-out that retype a device's line
	// by value.
	real map[string]string
}

// prepareIOS indexes the rendering's raw lines per section.
func (p *planner) prepareIOS(results map[string]devconf.SectionResult) {
	st := &iosState{entries: map[string][]iosEntry{}, byStem: map[string]map[string][]int{},
		used: map[string]map[int]bool{}, renderedKeys: map[string]bool{},
		kinds: map[string]map[string]bool{}, levels: map[string]bool{}, acls: map[string]bool{},
		real: map[string]string{}}
	p.ios = st
	for _, sec := range p.exp {
		if sec.Name == devconf.SectionSNMP {
			if m, err := devconf.CommunityLabels(devconf.FamilyIOS, sec.Lines); err == nil {
				st.real = m
			}
		}
		es := parseIOSExpected(sec)
		st.entries[sec.Name] = es
		st.byStem[sec.Name] = map[string][]int{}
		st.used[sec.Name] = map[int]bool{}
		for i, e := range es {
			st.byStem[sec.Name][e.stem] = append(st.byStem[sec.Name][e.stem], i)
			path := e.path()
			if k, ok := iosKey(path); ok {
				st.renderedKeys[k] = true
			}
			if len(path) > 1 {
				h := strings.Join(path[:len(path)-1], pathSep)
				if st.kinds[h] == nil {
					st.kinds[h] = map[string]bool{}
				}
				st.kinds[h][strings.Fields(path[len(path)-1])[0]] = true
				if strings.HasPrefix(path[0], "ip access-list ") {
					st.acls[path[0]] = true
				}
			} else if f := strings.Fields(path[0]); len(f) >= 4 && f[0] == "privilege" {
				if i := slices.Index(f, "level"); i >= 0 && i+1 < len(f) {
					st.levels[f[i+1]] = true
				}
			}
		}
	}
	st.login = p.opt.Login
	st.loginKnown = len(st.login) > 0
	if !st.loginKnown {
		st.login, st.loginKnown = LoginLeaves(p.cur)
	}
	st.enable = p.opt.EnableSecret
	if st.enable == "" {
		st.enable = enableOf(p.cur, results["aaa"].Notes)
	}
}

// parseIOSExpected reads a rendered section's lines (a submode's lines
// indented under the line that opens it) into entries with their canonical
// stem and the raw text.
func parseIOSExpected(sec devices.Section) []iosEntry {
	type item struct {
		indent int
		text   string
		mark   bool
		// banner is a login banner: text holds its lines (the opening line,
		// the text, the closing delimiter, joined by "\n") and stem its
		// compared form.
		banner bool
		stem   string
	}
	var items []item
	for i := 0; i < len(sec.Lines); i++ {
		raw := sec.Lines[i]
		trimmed := strings.TrimRight(raw, " \t\r")
		t := strings.TrimLeft(trimmed, " \t")
		if kind := blocks.BannerKindOf(t); len(trimmed) == len(t) && kind != "" {
			// the banner's lines are text up to the closing delimiter: a blank
			// line or a line that begins with '!' is part of it
			body, took, ok := blocks.DeviceBannerOf(kind, sec.Lines[i:])
			if ok {
				items = append(items, item{text: strings.Join(sec.Lines[i:i+took], "\n"), banner: true,
					stem: "banner " + kind + " " + devconf.MessageMark(body)})
			}
			i += took - 1
			continue
		}
		if t == "" || strings.HasPrefix(t, "!") {
			continue
		}
		items = append(items, item{indent: len(trimmed) - len(t), text: strings.Join(strings.Fields(t), " "), mark: i < len(sec.Secret) && sec.Secret[i]})
	}
	type frame struct {
		indent int
		text   string
	}
	var stack []frame
	var out []iosEntry
	for k, it := range items {
		for len(stack) > 0 && stack[len(stack)-1].indent >= it.indent {
			stack = stack[:len(stack)-1]
		}
		if it.banner {
			out = append(out, iosEntry{stem: it.stem, leaf: it.text})
			continue
		}
		if k+1 < len(items) && items[k+1].indent > it.indent && !items[k+1].banner {
			stack = append(stack, frame{it.indent, it.text})
			continue
		}
		var ctx []string
		var lines []string
		var marks []bool
		for d, f := range stack {
			ctx = append(ctx, f.text)
			lines = append(lines, strings.Repeat(" ", d)+f.text)
			marks = append(marks, false)
		}
		lines = append(lines, strings.Repeat(" ", len(ctx))+it.text)
		marks = append(marks, it.mark)
		// a community's name is labelled as in the whole section, so the
		// stem is the one the comparison gives the same statement
		stems, err := devconf.ElideIn("cisco", lines, marks, sec.Lines)
		if err != nil || len(stems) == 0 {
			continue
		}
		out = append(out, iosEntry{stem: stems[0], ctx: ctx, leaf: it.text, secret: it.mark})
	}
	return out
}

// unlabel is a compared statement with the labels of the strings the
// rendering holds ('<secret:2>') put back as those strings: the line as the
// device holds it. ok is false when a mark is left that the rendering cannot
// name (another community's '<other:1>', the bare mark of an older record).
func (st *iosState) unlabel(stem string) (string, bool) {
	replaced := false
	text := reMarks.ReplaceAllStringFunc(stem, func(m string) string {
		if v, ok := st.real[m]; ok {
			replaced = true
			return v
		}
		return m
	})
	return text, replaced && !reMarks.MatchString(text)
}

// take returns the rendered entry of a stem not yet used.
func (st *iosState) take(section, stem string) (iosEntry, bool) {
	for _, i := range st.byStem[section][stem] {
		if !st.used[section][i] {
			st.used[section][i] = true
			return st.entries[section][i], true
		}
	}
	return iosEntry{}, false
}

// iosKey is the key under which a statement replaces another in place: the
// method list's type, level and name; a server line's address; a singleton
// leaf of a block; the SNMP location and contact. ok is false for a
// statement that never replaces another (a list element).
func iosKey(path []string) (string, bool) {
	leaf := strings.Fields(path[len(path)-1])
	if len(leaf) == 0 {
		return "", false
	}
	ctx := path[:len(path)-1]
	if len(ctx) == 0 {
		switch {
		case leaf[0] == "aaa" && len(leaf) >= 3:
			switch {
			case leaf[1] == "authorization" && leaf[2] == "config-commands":
				return "aaa authorization config-commands", true
			case (leaf[1] == "authorization" || leaf[1] == "accounting") && leaf[2] == "commands" && len(leaf) >= 5:
				return strings.Join(leaf[:5], " "), true
			case len(leaf) >= 4 && (leaf[1] == "authentication" || leaf[1] == "authorization" || leaf[1] == "accounting"):
				return strings.Join(leaf[:4], " "), true
			case leaf[1] == "session-id":
				// one session id mode: 'common' replaces 'unique'
				return "aaa session-id", true
			}
		case leaf[0] == "ip" && len(leaf) >= 3 && (leaf[1] == "tacacs" || leaf[1] == "radius") && leaf[2] == "source-interface":
			// one source interface per protocol: a typed one replaces it
			return "ip " + leaf[1] + " source-interface", true
		case (leaf[0] == "tacacs-server" || leaf[0] == "radius-server") && len(leaf) >= 3 && leaf[1] == "host":
			return hostEntry(leaf), true
		case leaf[0] == "snmp-server" && len(leaf) >= 2 && (leaf[1] == "location" || leaf[1] == "contact"):
			return leaf[0] + " " + leaf[1], true
		case leaf[0] == "snmp-server" && len(leaf) >= 3 && leaf[1] == "trap-source":
			// one trap source: a typed one replaces it
			return "snmp-server trap-source", true
		case leaf[0] == "banner" && len(leaf) >= 2 && slices.Contains(blocks.BannerKinds, leaf[1]):
			// one banner of a kind: a typed one replaces it (0.2.7, the system
			// block; motd and exec 0.2.19)
			return "banner " + leaf[1], true
		case leaf[0] == "ip" && len(leaf) >= 4 && leaf[1] == "domain" && leaf[2] == "name" && leaf[3] != "vrf",
			leaf[0] == "ip" && len(leaf) == 3 && leaf[1] == "domain-name":
			// the legacy spelling is the same command
			return "ip domain name", true
		case leaf[0] == "ip" && len(leaf) >= 5 && leaf[1] == "domain" && leaf[2] == "name" && leaf[3] == "vrf":
			// one domain name per vrf: a typed one replaces the vrf's
			return "ip domain name vrf " + leaf[4], true
		case leaf[0] == "clock" && len(leaf) >= 3 && leaf[1] == "timezone":
			return "clock timezone", true
		case leaf[0] == "clock" && len(leaf) >= 3 && leaf[1] == "summer-time":
			return "clock summer-time", true
		case leaf[0] == "logging" && len(leaf) >= 3 && leaf[1] == "host":
			// one line per syslog host
			return "logging host " + leaf[2], true
		case leaf[0] == "logging" && len(leaf) >= 2 && (leaf[1] == "trap" || leaf[1] == "buffered" || leaf[1] == "origin-id"):
			return "logging " + leaf[1], true
		case leaf[0] == "service" && len(leaf) >= 3 && leaf[1] == "timestamps":
			// one line per kind: a typed one replaces the device's
			return "service timestamps " + leaf[2], true
		case leaf[0] == "login" && len(leaf) >= 2 && (leaf[1] == "on-failure" || leaf[1] == "on-success" || leaf[1] == "delay"):
			return "login " + leaf[1], true
		case leaf[0] == "security" && len(leaf) >= 3 && leaf[1] == "passwords" && leaf[2] == "min-length":
			return "security passwords min-length", true
		case leaf[0] == "security" && len(leaf) >= 5 && leaf[1] == "authentication" && leaf[2] == "failure" && leaf[3] == "rate":
			return "security authentication failure rate", true
		case leaf[0] == "ip" && len(leaf) >= 3 && leaf[1] == "ssh" && (leaf[2] == "version" || leaf[2] == "time-out" || leaf[2] == "authentication-retries"):
			return "ip ssh " + leaf[2], true
		case leaf[0] == "ntp" && len(leaf) >= 3 && leaf[1] == "server" && leaf[2] != "vrf" && leaf[2] != "ip" && leaf[2] != "ipv6":
			// one line per NTP server: a typed one replaces the device's of
			// the same host, whatever its options
			return "ntp server " + leaf[2], true
		case leaf[0] == "ntp" && len(leaf) >= 5 && leaf[1] == "server" && leaf[2] == "vrf" && leaf[4] != "ip" && leaf[4] != "ipv6":
			// the same, for a server reached in a vrf (another object than
			// the host without one)
			return "ntp server vrf " + leaf[3] + " " + leaf[4], true
		case leaf[0] == "snmp-server" && len(leaf) >= 3 && leaf[1] == "community" && leaf[2] != secretMark:
			// one line per community: a typed one replaces it (an older
			// record's bare mark stands for every community, so it keys none)
			return strings.Join(leaf[:3], " "), true
		case leaf[0] == "snmp-server" && len(leaf) >= 4 && leaf[1] == "host":
			// one line per trap host and community: a typed one replaces it,
			// whatever its version, port and types (0.2.7, the SNMP block's
			// hosts)
			if i := devconf.SNMPHostCommunity(leaf); i > 0 && leaf[i] != secretMark {
				return "snmp-server host " + devconf.SNMPHostID(leaf, i, leaf[i]), true
			}
		}
		return "", false
	}
	switch {
	case strings.HasPrefix(ctx[0], "tacacs server ") || strings.HasPrefix(ctx[0], "radius server "):
		return strings.Join(ctx, pathSep) + pathSep + leaf[0], true
	case isLoginLeafPath(path):
		// a line has one login method: a typed one replaces it
		return "line " + strings.Fields(ctx[0])[1] + " > login", true
	case strings.HasPrefix(ctx[0], "line vty ") && leaf[0] == "access-class" && len(leaf) >= 3:
		return "line vty > access-class " + leaf[len(leaf)-1], true
	}
	return "", false
}

// isLoginLeafPath reports 'line vty <range> > login ...' and 'line con N >
// login ...' (also 'no login').
func isLoginLeafPath(path []string) bool {
	if len(path) != 2 {
		return false
	}
	h := strings.Fields(path[0])
	if len(h) < 3 || h[0] != "line" || h[1] != "vty" && h[1] != "con" {
		return false
	}
	f := strings.Fields(path[1])
	return len(f) >= 1 && (f[0] == "login" || len(f) >= 2 && f[0] == "no" && f[1] == "login")
}

// lineRange reads the lines a 'line vty A [B]' or 'line con N' header covers.
func lineRange(header string) (kind string, lo, hi int, ok bool) {
	f := strings.Fields(header)
	if len(f) < 3 || f[0] != "line" || f[1] != "vty" && f[1] != "con" {
		return "", 0, 0, false
	}
	lo, err := strconv.Atoi(f[2])
	if err != nil {
		return "", 0, 0, false
	}
	hi = lo
	if len(f) >= 4 {
		if h, err := strconv.Atoi(f[3]); err == nil {
			hi = h
		}
	}
	return f[1], lo, hi, true
}

// within reports whether the lines of header a are all covered by header b.
func within(a, b string) bool {
	ka, alo, ahi, ok := lineRange(a)
	kb, blo, bhi, ok2 := lineRange(b)
	return ok && ok2 && ka == kb && alo >= blo && ahi <= bhi
}

// isBinding reports the access-class binding on the VTY lines, which is
// never emitted.
func isBinding(path []string) bool {
	return len(path) >= 2 && strings.HasPrefix(path[0], "line vty ") && strings.HasPrefix(path[len(path)-1], "access-class ")
}

func isACLHeader(s string) bool {
	return strings.HasPrefix(s, "ip access-list ") || strings.HasPrefix(s, "ipv6 access-list ")
}

// iosLineOf builds a Line from an entry.
func (p *planner) iosAdd(e iosEntry) Line {
	l := Line{Op: OpLine, Context: slices.Clone(e.ctx), Text: e.leaf}
	if e.secret {
		path := e.path()
		stemLeaf := path[len(path)-1]
		l.Secret = true
		l.Elided = shownSecret(stemLeaf)
		if p.opt.NoSecrets || e.noRaw {
			// MEDIUM 10: a value that could not be found is a placeholder,
			// never the stem's text with the value left out
			l.Text = placeholderOf(stemLeaf)
		} else {
			l.HasValue = true
		}
	}
	return l
}

// iosSection plans one IOS section.
func (p *planner) iosSection(name string, r devconf.SectionResult) secOut {
	var o secOut
	st := p.ios
	dev := p.cur.Sections[name].Lines

	var missing []iosEntry
	var extras []iosExtra
	var repush []iosEntry
	for _, l := range r.Lines {
		stem := stemOf(l)
		switch l.Op {
		case devconf.OpMissing:
			e, ok := st.take(name, stem)
			if !ok {
				path := strings.Split(stem, pathSep)
				e = iosEntry{stem: stem, ctx: path[:len(path)-1], leaf: path[len(path)-1], secret: l.Secret, noRaw: true}
			}
			missing = append(missing, e)
		case devconf.OpSame, devconf.OpNotVisible:
			e, ok := st.take(name, stem)
			if !l.Secret {
				continue
			}
			if p.opt.Secrets && ok {
				repush = append(repush, e)
				continue
			}
			if l.Op == devconf.OpSame {
				o.presentSecrets++
				o.presentKinds = append(o.presentKinds, secretWhat(devconf.FamilyIOS, stem))
			} else {
				o.hiddenSecrets++
			}
		case devconf.OpExtra:
			extras = append(extras, iosExtra{stem, l.Secret})
		}
	}

	var nos []Line
	var superseded = map[string][]iosExtra{} // key -> device statements replaced
	keep := func(stem, note string) {
		o.kept = append(o.kept, Kept{Section: name, Text: stem, Note: note})
	}

	// Rendered ACLs are planned as a whole (entry order matters).
	aclAdds, aclNos, aclPre, handled := p.iosACLs(name, dev, &o)
	// every ACL line answers the findings of its list (the entries and the order)
	for _, ls := range [][]Line{aclAdds, aclNos, aclPre} {
		for i := range ls {
			h := ls[i].Context[0]
			for _, l := range r.Lines {
				if l.Op != devconf.OpSame && (strings.HasPrefix(stemOf(l), h+pathSep) || strings.HasPrefix(l.Text, h+":")) {
					ls[i].For = append(ls[i].For, stemOf(l))
				}
			}
		}
	}

	// Missing statements.
	var addLines []Line
	var loginMissing []iosEntry
	var loginLines []Line
	// loginUsed marks the rendered leaves a device's explicit leaf replaced.
	loginUsed := map[int]bool{}
	// D117 (amended): the server entries that sit at the address the
	// standard's block takes (a legacy host line on a modern image, a named
	// block of another name), which IOS would refuse a second copy of. The
	// region removes them (and the command-authorization lists that name their
	// groups) before the standard is added; the unit is refused only when
	// nothing proves that the pasting session is a TACACS+ user.
	var forms, blocked []*oldForm
	var cmdLists []string
	if name == "aaa" {
		forms = p.legacyHostsToReplace(missing)
		cmdLists = p.affectedCmdLists(forms)
		if len(cmdLists) > 0 && !p.serverInUse() {
			forms = slices.DeleteFunc(slices.Clone(forms), func(f *oldForm) bool {
				if f.proto == "tacacs" {
					blocked = append(blocked, f)
					return true
				}
				return false
			})
			cmdLists = nil
		}
	}
	formOf := map[string]bool{}
	removedCmd := map[string]bool{}
	for _, f := range forms {
		for _, s := range f.stems {
			formOf[s] = true
		}
		for _, e := range f.entries {
			formOf[e.stem] = true
		}
	}
	for _, s := range cmdLists {
		removedCmd[s] = true
	}
	plannedGone := map[string]bool{}
	// D118 (12): command authorization waits until the server is proven to
	// this device.
	holdCmdAuth := name == "aaa" && !p.serverProven()
	for _, e := range missing {
		path := e.path()
		if holdCmdAuth && isCmdAuthStem(e.stem) {
			o.withheld = append(o.withheld, cmdAuthWithheldPrefix+e.stem)
			continue
		}
		if isACLHeader(path[0]) && st.acls[path[0]] {
			continue // planned with its ACL
		}
		if isBinding(path) {
			// DECISION: the access-class binding is never a line (the
			// walkthrough's commented step, as the lo0 application on
			// Junos); the block names it as the operator's step, and a
			// missing binding stays a '-' in the diff.
			o.withheld = append(o.withheld, "the access-class binding: "+e.stem)
			continue
		}
		if isLoginLeafPath(path) {
			// DECISION (BLOCKER 2): the rendered login leaf is typed under
			// the ranges the device shows with another leaf, never under
			// the rendered header: 'line vty 0 15' on a device that has
			// fewer lines would make them. Lines with no leaf are on the
			// default list once 'aaa new-model' is on.
			loginMissing = append(loginMissing, e)
			continue
		}
		l := p.iosAdd(e)
		l.Section = name
		l.For = []string{e.stem}
		addLines = append(addLines, l)
	}
	for _, e := range repush {
		path := e.path()
		if isBinding(path) {
			continue
		}
		l := p.iosAdd(e)
		// the value that was there is not known: the back-out says to type it
		note := "type again with its original secret: " + shownSecret(path[len(path)-1])
		if strings.HasPrefix(path[len(path)-1], "snmp-server community ") {
			note = "a community pushed by value: if the device did not have it before, remove it with 'no snmp-server community <name>'"
		}
		l.Undo = []Line{{Op: OpComment, Text: note}}
		addLines = append(addLines, l)
	}

	// Extras.
	missingKeys := map[string]bool{}
	for _, e := range missing {
		if k, ok := iosKey(e.path()); ok {
			missingKeys[k] = true
		}
	}
	for _, x := range extras {
		path := strings.Split(x.stem, pathSep)
		if formOf[x.stem] {
			// D117: an old server entry at the standard's address, or the
			// group entry that names it: removed first (buildOldFormLines),
			// the standard follows in the same paste
			continue
		}
		if isACLHeader(path[0]) {
			if handled[path[0]] {
				continue
			}
			keep(x.stem, "")
			continue
		}
		if isBinding(path) {
			keep(x.stem, "")
			continue
		}
		if isLoginLeafPath(path) {
			// DECISION: a device range with a login leaf inside a rendered
			// range gets the rendered leaf under its own header, and the
			// back-out types its old leaf again; a range that sticks out of
			// the rendered one is kept and said so.
			covered := slices.IndexFunc(loginMissing, func(e iosEntry) bool {
				return within(path[0], e.path()[0])
			})
			if covered >= 0 {
				loginUsed[covered] = true
				if !p.inPlain(name, x.stem) {
					o.inherited = append(o.inherited, x.stem)
				}
				loginLines = append(loginLines, Line{Op: OpLine, Section: name, Context: []string{path[0]},
					Text: loginMissing[covered].leaf, For: []string{x.stem, loginMissing[covered].stem},
					Undo: []Line{{Op: OpLine, Context: []string{path[0]}, Text: path[1]}}})
				continue
			}
			keep(x.stem, "a login method the rendered lines do not cover")
			continue
		}
		if k, ok := iosKey(path); ok && missingKeys[k] {
			// replaced in place by the rendered line
			if !p.inPlain(name, x.stem) {
				o.inherited = append(o.inherited, x.stem)
			}
			superseded[k] = append(superseded[k], x)
			continue
		}
		leaf := strings.Fields(path[len(path)-1])
		switch {
		case name == devconf.SectionSystem && len(path) == 1 && forbidTarget(p.expected(name).Forbid, path[0]) != "":
			// a service the system block requires to be absent: the whole
			// statement goes (once, whatever sits under it), and the back-out
			// types the device's line again
			target := forbidTarget(p.expected(name).Forbid, path[0])
			if i := slices.IndexFunc(nos, func(l Line) bool { return l.Text == target }); i >= 0 {
				nos[i].For = append(nos[i].For, x.stem)
				nos[i].Undo = append(nos[i].Undo, Line{Op: OpLine, Text: path[0]})
				continue
			}
			nos = append(nos, Line{Op: OpNo, Text: target, Section: name, For: []string{x.stem},
				Undo: []Line{{Op: OpLine, Text: path[0]}}})
		case len(path) == 1 && st.isStoredFormOnly(path[0]) != "":
			// D106: what the image adds or stores by itself is never a 'no'
			keep(x.stem, st.isStoredFormOnly(path[0]))
		case len(path) == 1 && leaf[0] == "aaa" && len(leaf) >= 5 && leaf[2] == "commands" &&
			(leaf[1] == "authorization" || leaf[1] == "accounting") && leaf[4] == "default":
			k, _ := iosKey(path)
			if st.renderedKeys[k] || x.secret {
				keep(x.stem, "")
				continue
			}
			plannedGone[x.stem] = true
			if !removedCmd[x.stem] {
				// (the removal of an old server entry takes it off first)
				nos = append(nos, Line{Op: OpNo, Text: path[0], Section: name, For: []string{x.stem},
					Undo: []Line{{Op: OpLine, Text: path[0]}}})
			}
			o.warnings = append(o.warnings, "a "+leaf[1]+" commands list for level "+leaf[3]+
				" is on the device and tacctl does not render that level: the block removes it ("+path[0]+")")
			if !p.inPlain(name, x.stem) {
				o.inherited = append(o.inherited, x.stem)
			}
		case len(path) == 1 && leaf[0] == "aaa" && len(leaf) >= 4 && leaf[1] == "authentication" && leaf[2] == "enable" && leaf[3] == "default":
			// the standard has no enable list: one that asks the server lets
			// anyone the server knows reach level 15 with their own password
			// ('default enable', what IOS does with no list, is no extra)
			nos = append(nos, Line{Op: OpNo, Text: path[0], Section: name, For: []string{x.stem},
				Undo: []Line{{Op: OpLine, Text: path[0]}}})
			if !p.inPlain(name, x.stem) {
				o.inherited = append(o.inherited, x.stem)
			}
		case len(path) >= 2 && st.kinds[strings.Join(path[:len(path)-1], pathSep)] != nil &&
			st.kinds[strings.Join(path[:len(path)-1], pathSep)][leaf[0]] && (strings.HasPrefix(path[0], "tacacs server ") ||
			strings.HasPrefix(path[0], "radius server ") || strings.HasPrefix(path[0], "aaa group server ")):
			nos = append(nos, Line{Op: OpNo, Context: path[:len(path)-1], Text: path[len(path)-1], Section: name, For: []string{x.stem},
				Undo: []Line{{Op: OpLine, Context: path[:len(path)-1], Text: path[len(path)-1]}}})
		case len(path) == 1 && leaf[0] == "privilege" && len(leaf) >= 5 && leaf[1] == "exec":
			// HIGH 7: 'privilege configure|interface level N ...' is the
			// operator's, whatever the level
			li := slices.Index(leaf, "level")
			if li >= 0 && li+1 < len(leaf) && st.levels[leaf[li+1]] {
				nos = append(nos, Line{Op: OpNo, Text: path[0], Section: name, For: []string{x.stem},
					Undo: []Line{{Op: OpLine, Text: path[0]}}})
				if !p.inPlain(name, x.stem) {
					o.inherited = append(o.inherited, x.stem)
				}
				continue
			}
			keep(x.stem, "")
		case len(path) == 1 && leaf[0] == "snmp-server" && len(leaf) >= 3 && leaf[1] == "community" && leaf[2] == secretMark:
			// a record of an older tacctl: whose community it is cannot be told
			keep(x.stem, communityNotVisible)
		default:
			keep(x.stem, "")
		}
	}

	// A rendered login leaf that replaced nothing: the lines it names have no
	// leaf (they are on the default list once 'aaa new-model' is on), or the
	// device does not have them at all. Only the second is a finding.
	//
	// The console is the exception (D107): it is never implicit. A device
	// whose console has no explicit leaf uses the default list once 'aaa
	// new-model' is on, which is not the standard's CONSOLE list, so the
	// leaf is typed under the console header the device always has.
	for i, e := range loginMissing {
		header := e.path()[0]
		switch kind, _, _, _ := lineRange(header); {
		case !p.linesKnown(header):
			o.withheld = append(o.withheld, "the login method of lines the record does not show: "+e.stem)
		case kind == "con" && !loginUsed[i]:
			loginLines = append(loginLines, Line{Op: OpLine, Section: name, Context: []string{header}, Text: e.leaf,
				For:  []string{e.stem},
				Undo: []Line{{Op: OpNo, Context: []string{header}, Text: e.leaf}}})
		}
	}

	// D117: the lines that replace the old server entries: command
	// authorization off, the group entries, the entries themselves, and (typed
	// again at the end of the region) the lists that were taken off.
	var preNos []Line
	if name == "aaa" && len(forms) > 0 {
		of := p.buildOldFormLines(name, forms, cmdLists, plannedGone)
		preNos = slices.Concat(of.cmd, of.entries, of.forms)
		var names []string
		for _, f := range forms {
			names = append(names, f.removal())
		}
		msg := "the server entry " + strings.Join(names, ", ") + " is at the address of the standard server, and IOS refuses a second entry " +
			"with the same address and key: the region removes it (and the group entries that name it) before it adds the standard block, and the back-out puts it back"
		if len(cmdLists) > 0 {
			msg += "; command authorization is taken off first and typed again last, while the server still answers"
		}
		o.warnings = append(o.warnings, msg)
		addLines = append(addLines, of.point...)
		for _, s := range cmdLists {
			if plannedGone[s] {
				continue
			}
			if k, ok := iosKey(strings.Split(s, pathSep)); ok && missingKeys[k] {
				continue // typed again by the plan, as rendered
			}
			addLines = append(addLines, Line{Op: OpLine, Text: s, Section: name, Undo: []Line{{Op: OpNo, Text: s}}})
		}
	}

	// Undo lines for the adds: retype what was replaced, or remove.
	devHeaders := map[string]bool{}
	for _, s := range dev {
		devHeaders[strings.Split(s, pathSep)[0]] = true
	}
	var finalAdds []Line
	for _, l := range addLines {
		l.Section = name
		if len(l.Undo) > 0 {
			finalAdds = append(finalAdds, l)
			continue
		}
		path := append(slices.Clone(l.Context), l.Text)
		undo := Line{Op: OpNo, Context: slices.Clone(l.Context), Text: l.Text}
		// a secret line holds the value: its key is the compared
		// statement's, where the community is a label
		keyPath := path
		if l.Secret && len(l.For) > 0 {
			keyPath = strings.Split(l.For[0], pathSep)
		}
		if k, ok := iosKey(keyPath); ok {
			if sup := superseded[k]; len(sup) > 0 {
				undone := 0
				for _, s := range sup {
					l.For = append(l.For, s.stem)
					if removedCmd[s.stem] {
						// taken off first: the back-out of that removal types it
						// again, and this line is taken off before it
						continue
					}
					undone++
					if s.secret {
						// The string of a rendered community is known: the
						// device's line is typed again by value (placeholders
						// with --no-secrets).
						if t, ok := st.unlabel(s.stem); ok && !strings.Contains(s.stem, pathSep) {
							u := Line{Op: OpLine, Text: t, Secret: true, HasValue: true, Elided: s.stem}
							if p.opt.NoSecrets {
								u.Text, u.HasValue = placeholderOf(s.stem), false
							}
							l.Undo = append(l.Undo, u)
							continue
						}
						// MEDIUM 9: the device's own line is not in the
						// record (its secret is elided): the back-out says
						// to type it again with its original value
						l.Undo = append(l.Undo, Line{Op: OpComment, Text: "type again with its original secret: " + shownSecret(s.stem)})
						continue
					}
					if reIOSBannerStem.MatchString(s.stem) {
						// only the size and a digest of the device's banner are
						// kept: it cannot be typed again
						kind := blocks.BannerKindOf(s.stem)
						l.Undo = append(l.Undo, Line{Op: OpComment, Text: "the device had a " + kind + " banner that tacctl keeps no text of (" +
							strings.TrimPrefix(s.stem, "banner "+kind+" ") + "): put it back from the saved configuration " +
							"('configure replace' with the archived or the startup configuration), or type it again from what you have"})
						continue
					}
					sp := strings.Split(s.stem, pathSep)
					l.Undo = append(l.Undo, Line{Op: OpLine, Context: sp[:len(sp)-1], Text: sp[len(sp)-1]})
				}
				if undone > 0 {
					finalAdds = append(finalAdds, l)
					continue
				}
			}
		}
		switch {
		case len(l.Context) == 0 && systemUndo(&undo, l.Text):
			// the system block's statements and the trap source are undone as
			// the device takes them (a key by its number, never its value)
		case l.Secret:
			undo.Text = undoOfSecret(path, l)
			if strings.HasPrefix(undo.Text, "snmp-server community ") {
				// the community's name is the secret: the line holds it
				// (or the placeholder), and anything that shows it elides it
				undo.Secret, undo.HasValue = true, l.HasValue
				undo.Elided = "snmp-server community " + secretMark
				if f := strings.Fields(l.Elided); len(f) >= 3 && isMark(f[2]) {
					undo.Elided = strings.Join(f[:3], " ")
				}
			}
			if strings.HasPrefix(undo.Text, "snmp-server host ") {
				undo = iosHostUndo(l)
			}
		case len(l.Context) == 0 && strings.HasPrefix(l.Text, "tacacs-server host "):
			undo.Text = hostEntry(strings.Fields(l.Text))
		}
		// a block the paste created goes with one 'no <header>'; a line
		// header ('line vty 0 15') is never removed, only the leaf
		if len(l.Context) > 0 && !devHeaders[l.Context[0]] && removableHeader(l.Context[0]) {
			undo = Line{Op: OpNo, Text: l.Context[0]}
		}
		l.Undo = []Line{undo}
		finalAdds = append(finalAdds, l)
	}

	finalAdds = append(finalAdds, loginLines...)

	// The system block's NTP lines go in the order IOS needs: the keys, the
	// trusted keys, the servers that name them, and 'ntp authenticate' last
	// (the statements before them keep their order).
	if name == devconf.SectionSystem {
		slices.SortStableFunc(finalAdds, func(a, b Line) int { return systemRank(a) - systemRank(b) })
		for _, l := range finalAdds {
			if n := longestBannerLine(l.Text); n > iosMaxTypedLine {
				o.warnings = appendNew(o.warnings, "a line of the login banner is "+strconv.Itoa(n)+" characters, and IOS takes at most "+
					strconv.Itoa(iosMaxTypedLine)+" on a typed line: shorten it in the system block")
			}
		}
	}

	// Order inside the section. DECISION: roles removes before it adds (a
	// 'no privilege exec level 7 ping' after 'privilege exec all level 7
	// ping' would take the new assignment with it); aaa and the lists add
	// first and remove after (new before no, D106). The aaa unit is in the
	// order of aaaRank (D118): 'aaa new-model', the server, the group, the
	// source interface, the login lists, exec authorization, an enable list
	// (the standard has none; an operator's template may), accounting, the
	// session id, then the removals (an enable list the device has); the
	// line leaves and the command authorization are moved to the end of the
	// block by Plan.
	switch name {
	case "aaa":
		finalAdds = append(slices.Clone(preNos), finalAdds...)
		slices.SortStableFunc(finalAdds, func(a, b Line) int { return aaaRank(a) - aaaRank(b) })
		o.lines = append(finalAdds, nos...)
	case "roles":
		o.lines = append(nos, finalAdds...)
	default:
		// the ACL first (the community refers to it), then the rest
		o.lines = slices.Concat(aclPre, aclAdds, finalAdds, aclNos, nos)
	}
	for i := range o.lines {
		o.lines[i].Section = name
	}
	if len(o.inherited) > 0 {
		o.refused = "inherited from a group: change the group by hand (" + strings.Join(dedupe(o.inherited), "; ") + ")"
		o.lines = nil
		return o
	}

	// the aaa unit's guards (D106, D117, D118)
	if name == "aaa" && len(o.lines) > 0 {
		if len(blocked) > 0 {
			// D117: the old server entry would have to go while command
			// authorization is on, and nothing shows that the pasting session
			// is a TACACS+ user (no server of the scope's is in use): its
			// commands would be denied once the group is empty. The unit is
			// refused, the by-hand steps are outside it.
			o.lines = nil
			o.refused = "this device runs the legacy server form with command authorization: migrate it from the console as a user that reaches privilege 15 there (the steps are below the region)"
			o.byHand = p.migrationSteps(blocked)
			return o
		}
		addsModel := slices.ContainsFunc(missing, func(e iosEntry) bool { return e.stem == "aaa new-model" })
		if addsModel {
			hasExec := slices.ContainsFunc(missing, func(e iosEntry) bool {
				return strings.HasPrefix(e.stem, "aaa authorization exec default ")
			})
			if !hasExec {
				o.lines = nil
				o.refused = "the block would turn 'aaa new-model' on without 'aaa authorization exec default': every new login would land at privilege 1"
				return o
			}
			// [A: WP13.1b records the login leaves; until it merges the accessor
			// says unknown and this refuses] (D106 (ii)).
			if !st.loginKnown {
				o.lines = nil
				cmd := "tacctl device config pull"
				if p.opt.Device != "" {
					cmd += " " + p.opt.Device
				}
				o.refused = "the pull has no vty and console login leaves (a pull made before they were read) and 'no aaa new-model' does not put 'login local' back: run '" + cmd + "' first"
				o.refusedKind = KindNotPlannable
				return o
			}
			// D118 (0): turning AAA on in front of the local database of a
			// device that has no local user at privilege 15 leaves nothing to fall
			// back to when the server does not answer: the unit is refused.
			if has, known := localPriv15(p.cur); known && !has {
				o.lines = nil
				o.refused = "the device has no local user at privilege 15 and this block turns 'aaa new-model' on: add the break-glass user first (walkthrough Step 0), then plan again"
				return o
			}
		}
		if st.enable == "absent" {
			o.warnings = append(o.warnings, "the device has no enable secret: with the server unreachable, level 15 is reached only through the local user and 'aaa authorization exec'; set an enable secret first if you want a second way")
		}
		// M4: with AAA in front of the local database and no local user at
		// privilege 15, a server that rejects (wrong key, an unfilled
		// --no-secrets value, a server down) leaves no way in on the
		// console or the vty.
		if slices.ContainsFunc(o.lines, func(l Line) bool {
			return l.Op == OpLine && len(l.Context) == 0 && (l.Text == "aaa new-model" ||
				strings.HasPrefix(l.Text, "aaa authentication login ") || strings.HasPrefix(l.Text, "aaa authorization exec "))
		}) {
			switch has, known := localPriv15(p.cur); {
			case known && !has:
				p.noLocal = true
				o.warnings = append(o.warnings, "the device has no local user at privilege 15 ('username <name> privilege 15 secret ...'): if the server cannot be reached or does not answer (wrong key, a value not filled in, server down) a new session on the console or the vty cannot get in; create the local user first, by hand")
			case !known:
				o.warnings = append(o.warnings, "the pull does not show the device's local users, so a local user at privilege 15 could not be checked: make sure one exists before you paste, or a server that does not answer leaves no way in")
			}
		}
	}

	// the access-class check (D106, mgmt-acl)
	if name == "mgmt-acl" && len(o.lines) > 0 {
		if msg, warn := p.iosFromCheck(); msg != "" {
			if warn {
				o.warnings = append(o.warnings, msg)
			} else {
				o.lines = nil
				o.refused = msg
				return o
			}
		}
	}

	// the why-line: the rows of the lines in the section; the block's rows
	// are led by one sentence that names the block
	blockWhy := false
	for _, row := range iosOwned {
		if row.Section != name {
			continue
		}
		for _, l := range o.lines {
			if p.iosRow(name, l) == row.ID {
				if row.Block && !blockWhy && name == devconf.SectionSNMP {
					blockWhy = true
					what := "(its communities, access lists, trap hosts and 'enable traps' lines)"
					if p.blk != nil && p.blk.trapSource {
						what = "(its communities, access lists, trap hosts, trap source and 'enable traps' lines)"
					}
					o.why = append(o.why, "the SNMP block of "+p.blocksWords(name)+" "+what)
				}
				if w := p.whyOf(row); !slices.Contains(o.why, w) {
					o.why = append(o.why, w)
				}
				break
			}
		}
	}
	// D106: a rendered line the image accepts but does not store is a
	// permanent '-': it is typed every time (typing it again is harmless)
	// and the block says so once.
	if name == "roles" && slices.ContainsFunc(o.lines, func(l Line) bool { return l.Op == OpLine }) {
		o.why = append(o.why, "(accepted but not stored by some images: a permanent '-' in the diff is then expected)")
	}
	if name == "aaa" && len(o.lines) > 0 && slices.ContainsFunc(o.lines, func(l Line) bool { return l.Text == "aaa new-model" && len(l.Context) == 0 }) {
		// the sample's text (plan §4b)
		o.why = []string{"the server, the group and the method lists tacctl renders; 'aaa authorization exec' is in the same paste on purpose: without it every new login lands at privilege 1"}
	}
	return o
}

// iosRow is iosRowID for a line of this plan: a line the rendering took from
// a scope's SNMP block belongs to the block's row of its kind.
func (p *planner) iosRow(section string, l Line) string {
	id := iosRowID(section, l)
	if p.blk == nil || !p.blk.ios || section != devconf.SectionSNMP {
		return id
	}
	text := l.Text
	if l.Secret && l.Elided != "" {
		text = l.Elided
	}
	stem := strings.Join(append(slices.Clone(l.Context), text), pathSep)
	switch kind, _ := p.blk.iosKind(stem); kind {
	case "community":
		return "ios.snmp.block-community"
	case "acl":
		return "ios.snmp.block-acl"
	case "host":
		return "ios.snmp.block-host"
	case "traps":
		return "ios.snmp.block-traps"
	case "trap-source":
		return "ios.snmp.block-trap-source"
	}
	return id
}

// forbidTarget is the statement of forbid that the device's statement is at or
// under ("" when it is none).
func forbidTarget(forbid []string, statement string) string {
	w := strings.Fields(statement)
	for _, f := range forbid {
		fw := strings.Fields(f)
		if len(w) >= len(fw) && slices.Equal(w[:len(fw)], fw) {
			return f
		}
	}
	return ""
}

// iosRowID names the ownership row a line of a section belongs to.
func iosRowID(section string, l Line) string {
	t := l.Text
	c0 := firstCtx(l)
	if l.Op == OpNo && section == devconf.SectionSystem {
		for _, r := range iosOwned {
			if r.Mode == ModeAbsent && r.Pattern == t {
				return r.ID
			}
		}
	}
	switch {
	case strings.HasPrefix(c0, "ip access-list "):
		return "ios." + section + ".acl"
	case strings.HasPrefix(c0, "tacacs server "):
		return "ios.aaa.server-block"
	case strings.HasPrefix(c0, "radius server "):
		return "ios.aaa.radius-block"
	case strings.HasPrefix(c0, "aaa group server tacacs+ "):
		return "ios.aaa.group"
	case strings.HasPrefix(c0, "aaa group server radius "):
		return "ios.aaa.radius-group"
	case strings.HasPrefix(t, "tacacs-server host "):
		return "ios.aaa.legacy-host"
	case strings.HasPrefix(t, "radius-server host "):
		return "ios.aaa.legacy-radius-host"
	case strings.HasPrefix(c0, "line con ") && strings.HasPrefix(t, "login authentication "):
		return "ios.aaa.console-leaf"
	case strings.HasPrefix(c0, "line vty ") && strings.HasPrefix(t, "login authentication "):
		return "ios.aaa.vty-leaf"
	case l.Op == OpNo && strings.HasPrefix(t, "aaa ") && strings.Contains(t, " commands "):
		return "ios.aaa.commands-level"
	case strings.HasPrefix(t, "aaa authorization config-commands"):
		return "ios.aaa.config-commands"
	case strings.HasPrefix(t, "aaa authentication login "+iosConsoleList+" "):
		return "ios.aaa.console-list"
	case strings.HasPrefix(t, "aaa authentication enable "):
		return "ios.aaa.enable-list"
	case strings.HasPrefix(t, "aaa session-id "):
		return "ios.aaa.session-id"
	case strings.HasPrefix(t, "ip tacacs source-interface "), strings.HasPrefix(t, "ip radius source-interface "):
		return "ios.aaa.source-interface"
	case strings.HasPrefix(t, "aaa "):
		return "ios.aaa.method-list"
	case strings.HasPrefix(t, "privilege "):
		return "ios.roles.privilege"
	case strings.HasPrefix(t, "snmp-server community"):
		return "ios.snmp.community"
	case strings.HasPrefix(t, "snmp-server location"):
		return "ios.snmp.location"
	case strings.HasPrefix(t, "snmp-server contact"):
		return "ios.snmp.contact"
	case strings.HasPrefix(t, "snmp-server trap-source "):
		return "ios.snmp.block-trap-source"
	case strings.HasPrefix(t, "banner login "):
		return "ios.system.banner"
	case strings.HasPrefix(t, "banner motd "):
		return "ios.system.banner-motd"
	case strings.HasPrefix(t, "banner exec "):
		return "ios.system.banner-exec"
	case strings.HasPrefix(t, "ip domain name "):
		return "ios.system.domain-name"
	case strings.HasPrefix(t, "ip domain list "):
		return "ios.system.domain-list"
	case strings.HasPrefix(t, "clock timezone "):
		return "ios.system.timezone"
	case strings.HasPrefix(t, "ip name-server "):
		return "ios.system.name-server"
	case strings.HasPrefix(t, "ntp server "):
		return "ios.system.ntp-server"
	case strings.HasPrefix(t, "ntp authentication-key "):
		return "ios.system.ntp-key"
	case strings.HasPrefix(t, "ntp trusted-key "):
		return "ios.system.ntp-trusted-key"
	case t == "ntp authenticate":
		return "ios.system.ntp-authenticate"
	case strings.HasPrefix(t, "logging host "):
		return "ios.system.logging-host"
	case strings.HasPrefix(t, "logging trap "):
		return "ios.system.logging-trap"
	case strings.HasPrefix(t, "logging buffered "):
		return "ios.system.logging-buffered"
	case strings.HasPrefix(t, "logging origin-id "):
		return "ios.system.logging-origin-id"
	case strings.HasPrefix(t, "service timestamps "):
		return "ios.system.timestamps"
	case strings.HasPrefix(t, "login on-failure "):
		return "ios.system.login-on-failure"
	case strings.HasPrefix(t, "login on-success "):
		return "ios.system.login-on-success"
	case strings.HasPrefix(t, "login delay "):
		return "ios.system.login-delay"
	case strings.HasPrefix(t, "security passwords min-length "):
		return "ios.system.passwords-min-length"
	case strings.HasPrefix(t, "security authentication failure rate "):
		return "ios.system.auth-failure-rate"
	case strings.HasPrefix(t, "ip ssh version "):
		return "ios.system.ssh-version"
	case strings.HasPrefix(t, "ip ssh time-out "):
		return "ios.system.ssh-timeout"
	case strings.HasPrefix(t, "ip ssh authentication-retries "):
		return "ios.system.ssh-retries"
	case strings.HasPrefix(t, "clock summer-time "):
		return "ios.system.summer-time"
	}
	return ""
}

// iosMaxTypedLine is the longest line IOS takes when it is typed or pasted.
const iosMaxTypedLine = 255

// longestBannerLine is the length of the longest line of a banner's text (0
// for a line that is no banner).
func longestBannerLine(text string) int {
	if blocks.BannerKindOf(text) == "" || !strings.Contains(text, "\n") {
		return 0
	}
	n := 0
	for _, l := range strings.Split(text, "\n") {
		n = max(n, len(l))
	}
	return n
}

// systemRank orders the lines of the system section as IOS needs them (M4).
func systemRank(l Line) int {
	t := l.Text
	switch {
	case strings.HasPrefix(t, "ntp authentication-key "):
		return 1
	case strings.HasPrefix(t, "ntp trusted-key "):
		return 2
	case strings.HasPrefix(t, "ntp server "):
		return 3
	case t == "ntp authenticate":
		return 4
	}
	return 0
}

// reIOSBannerStem is the compared form of a banner (login, motd or exec).
var reIOSBannerStem = regexp.MustCompile(`^banner (login|motd|exec) <message: [0-9]+ lines, [0-9]+ characters, id [0-9a-f]{8}>$`)

// systemUndo sets the text of an undo line to the system statement's own
// take-away (iosSystemUndo): false when the text is none of them.
func systemUndo(undo *Line, text string) bool {
	t, ok := iosSystemUndo(text)
	if ok {
		undo.Text = t
	}
	return ok
}

// iosSystemUndo is the line that takes a typed system statement of the block
// away again, as the device takes it: the statement without its value for a
// single (a 'no ip domain name', 'no clock timezone', 'no banner login'), with
// the entry for a list ('no ip name-server A'), the server by its host and a
// key by its number. ok is false for a line that is none of them.
func iosSystemUndo(text string) (string, bool) {
	f := strings.Fields(text)
	if len(f) < 2 {
		return "", false
	}
	switch {
	case f[0] == "banner" && slices.Contains(blocks.BannerKinds, f[1]):
		return "banner " + f[1], true
	case f[0] == "ip" && len(f) >= 5 && f[1] == "domain" && f[2] == "name" && f[3] == "vrf":
		return strings.Join(f[:5], " "), true
	case f[0] == "ip" && len(f) >= 6 && f[1] == "domain" && f[2] == "list" && f[3] == "vrf":
		return strings.Join(f[:6], " "), true
	case f[0] == "ip" && len(f) >= 4 && f[1] == "domain" && f[2] == "name":
		return "ip domain name", true
	case f[0] == "ip" && len(f) >= 4 && f[1] == "domain" && f[2] == "list":
		return strings.Join(f[:4], " "), true
	case f[0] == "ip" && len(f) >= 5 && f[1] == "name-server" && f[2] == "vrf":
		return strings.Join(f[:5], " "), true
	case f[0] == "ntp" && len(f) >= 5 && f[1] == "server" && f[2] == "vrf":
		return strings.Join(f[:5], " "), true
	case f[0] == "clock" && f[1] == "timezone":
		return "clock timezone", true
	case f[0] == "ip" && f[1] == "name-server" && len(f) >= 3:
		return strings.Join(f[:3], " "), true
	case f[0] == "ntp" && len(f) >= 3 && f[1] == "server":
		return strings.Join(f[:3], " "), true
	case f[0] == "ntp" && len(f) >= 3 && (f[1] == "authentication-key" || f[1] == "trusted-key"):
		return strings.Join(f[:3], " "), true
	case f[0] == "ntp" && f[1] == "authenticate":
		return "ntp authenticate", true
	case f[0] == "snmp-server" && f[1] == "trap-source":
		return "snmp-server trap-source", true
	case f[0] == "logging" && len(f) >= 3 && f[1] == "host":
		return "logging host " + f[2], true
	case f[0] == "logging" && (f[1] == "trap" || f[1] == "buffered" || f[1] == "origin-id"):
		return "logging " + f[1], true
	case f[0] == "service" && len(f) >= 3 && f[1] == "timestamps":
		return "service timestamps " + f[2], true
	case f[0] == "login" && (f[1] == "on-failure" || f[1] == "on-success" || f[1] == "delay"):
		return "login " + f[1], true
	case f[0] == "security" && len(f) >= 3 && f[1] == "passwords" && f[2] == "min-length":
		return "security passwords min-length", true
	case f[0] == "security" && len(f) >= 4 && f[1] == "authentication" && f[2] == "failure" && f[3] == "rate":
		return "security authentication failure rate", true
	case f[0] == "ip" && len(f) >= 3 && f[1] == "ssh":
		return "ip ssh " + f[2], true
	case f[0] == "clock" && f[1] == "summer-time":
		return "clock summer-time", true
	}
	return "", false
}

// IOSStoredForm is a row of the stored-forms table (D106, the spike's "What
// show running-config stores"): what the image adds or stores by itself,
// and what the planner does about it. The extractor tolerates most of them
// before the planner sees them (devconf: privilegeParents,
// withoutImplicitIOS); these rows are the planner's own guard that none of
// them is ever typed as a 'no'.
type IOSStoredForm struct {
	ID   string
	What string
	// Rule is the planner's behaviour.
	Rule string
}

// iosStoredForms is the table. A row without a test fails TestStoredForms.
var iosStoredForms = []IOSStoredForm{
	{"ios.stored.parent", "'privilege exec level N <word>' lines the image adds for the words leading to a rendered command",
		"never a 'no'; kept with a note, the typed form is the rendered line"},
	{"ios.stored.queue-length", "'snmp-server queue-length 100' beside the first community",
		"never a 'no'; kept with a note"},
	{"ios.stored.chassis-id", "'snmp-server chassis-id' (an empty value) that IOSv 15.6 prints by itself once a community is set and keeps after 'no snmp-server community' [S: lab IOSv 15.6(2)T]",
		"never a 'no'; kept with a note (devconf's implicit-lines rule covers the queue length only: flagged)"},
	{"ios.stored.ios15-privilege-default", "'privilege exec level <default> <cmd>' that IOS 15.x keeps in place of a removed 'privilege exec level N <cmd>' (the command's own default level: 'level 15 clear counters', 'level 1 ping', parents 'level 15 clear ip', 'level 1 show') [S: lab IOSv 15.6(2)T]",
		"never a 'no': the comparison leaves the line out when the rendering has no line for the command (devconf: IOSDefaultPrivilege), so it is no extra, no report item and no region line; where the rendering has one, the typed line replaces it and the guard keeps it with a note"},
	{"ios.stored.truncated", "'privilege exec all level N <words>' stored as a prefix of the typed words on an image that lacks the last word",
		"typed as rendered every time (the extractor reads it as '-' until WP13.1b); the stored prefix is never a 'no'"},
	{"ios.stored.not-stored", "a rendered line the image accepts and does not store (a command whose last words it does not know: it stores the words it knows)",
		"a permanent '-': typed every time (typing it again is idempotent) and noted once in the section's why-line"},
}

// IOSStoredForms returns the stored-forms table.
func IOSStoredForms() []IOSStoredForm { return slices.Clone(iosStoredForms) }

// isStoredFormOnly names why a statement of the device is the image's own
// (a note), or "" when it is not.
func (st *iosState) isStoredFormOnly(stmt string) string {
	f := strings.Fields(stmt)
	if len(f) >= 3 && f[0] == "snmp-server" && f[1] == "queue-length" {
		return "added by the image beside the first community"
	}
	if len(f) >= 2 && f[0] == "snmp-server" && f[1] == "chassis-id" {
		return "printed by the image once a community is set, and kept when it is removed"
	}
	if len(f) >= 5 && f[0] == "privilege" && f[1] == "exec" {
		li := slices.Index(f, "level")
		if li < 0 || li+2 >= len(f) {
			return ""
		}
		if i := slices.Index(f, "all"); i >= 0 && i < li {
			return "" // an 'all' on the device covers more than the rendering says
		}
		// [S: lab IOSv 15.6(2)T] the line IOS 15.x leaves where the command
		// is at its own default level (devconf's table, which the comparison
		// uses to leave such a line out when the rendering has none for the
		// command; this guard is for the one the rendering does have, which
		// the paste replaces)
		if def, ok := devconf.IOSDefaultPrivilege(strings.Join(f[li+2:], " ")); ok && def == f[li+1] {
			return "the command's own default level, which IOS 15.x keeps after a 'no'"
		}
		// [S: lab IOSv 15.6(2)T] a parent-shaped line at level 1 or 15 (the
		// levels IOS stores a default at): 'level 1 clear', 'level 15 clear
		// ip' stay behind for the words of a rendered line of another level
		if lvl := f[li+1]; lvl == "1" || lvl == "15" {
			words := f[li+2:]
			for _, r := range st.entries["roles"] {
				g := strings.Fields(r.path()[0])
				gl := slices.Index(g, "level")
				if gl < 0 || gl+2 >= len(g) {
					continue
				}
				gw := g[gl+2:]
				if len(gw) > len(words) && slices.Equal(gw[:len(words)], words) {
					return "the command's own default level, which IOS 15.x keeps after a 'no'"
				}
			}
		}
		mine := f
		for _, r := range st.entries["roles"] {
			g := strings.Fields(r.path()[0])
			if i := slices.Index(g, "all"); i >= 0 && i+1 < len(g) && g[i+1] == "level" {
				g = slices.Delete(g, i, i+1)
			}
			// a proper word-prefix of a rendered line at the same level and
			// mode: a parent the image adds, or the truncated form of one
			if len(g) > len(mine) && slices.Equal(g[:len(mine)], mine) {
				return "a parent line the image adds by itself"
			}
		}
	}
	return ""
}

// iosExtra is a '+' statement of the comparison.
type iosExtra struct {
	stem   string
	secret bool
}

// OwnedByID returns a table row by its ID.
func OwnedByID(family, id string) OwnedRow {
	for _, r := range OwnedTable(family) {
		if r.ID == id {
			return r
		}
	}
	return OwnedRow{}
}

// undoOfSecret is the 'no' of a secret line without its value (a community's
// name is the secret: its placeholder or value is the line's own).
func undoOfSecret(path []string, l Line) string {
	t := l.Text
	switch {
	case strings.HasPrefix(t, "tacacs-server host ") || strings.HasPrefix(t, "radius-server host "):
		return hostEntry(strings.Fields(t))
	case strings.HasPrefix(t, "snmp-server community "):
		f := strings.Fields(t)
		return strings.Join(f[:3], " ")
	case strings.HasPrefix(t, "snmp-server host "):
		// the entry as IOS keys it, without its notification types
		return strings.Join(hostNoWords(strings.Fields(t)), " ")
	}
	if f := strings.Fields(t); len(f) > 0 {
		return f[0]
	}
	return t
}

// hostNoWords are the words of the 'no' line that takes an 'snmp-server host'
// line's entry away: the line up to and including its 'udp-port N', with the
// version and the kind as typed and without the notification types. IOS keeps
// a host of another kind or port as an entry of its own, so the kind and the
// port are part of the line, and a 'no' that names the types removes only
// them.
func hostNoWords(f []string) []string {
	i := devconf.SNMPHostCommunity(f)
	if i < 0 {
		return f
	}
	n := i + 1
	if n+1 < len(f) && f[n] == "udp-port" {
		n += 2
	}
	return f[:n]
}

// iosHostUndo is the back-out line of a typed 'snmp-server host' line: 'no'
// and the line as hostNoWords cuts it. A host names the community its
// notifications are sent with, so the line is a secret like the line it
// undoes, with the community as its label where it is shown.
func iosHostUndo(l Line) Line {
	text := strings.Join(hostNoWords(strings.Fields(l.Text)), " ")
	undo := Line{Op: OpNo, Text: text, Secret: true, HasValue: l.HasValue, Elided: text}
	if f := strings.Fields(l.Elided); devconf.SNMPHostCommunity(f) > 0 {
		undo.Elided = strings.Join(hostNoWords(f), " ")
	}
	return undo
}

// hostEntry is the text a 'no' line takes to remove a server entry, as the
// device stores it: 'tacacs-server host <address>' is keyed by its address;
// IOS keys a RADIUS host on the address and its ports, so 'radius-server host
// <address> auth-port N acct-port M' keeps them and drops the rest (timeout,
// key). f are the entry's words.
func hostEntry(f []string) string {
	if len(f) < 3 {
		return strings.Join(f, " ")
	}
	out := slices.Clone(f[:3])
	if f[0] == "radius-server" {
		for i := 3; i+1 < len(f); i++ {
			if f[i] == "auth-port" || f[i] == "acct-port" {
				out = append(out, f[i], f[i+1])
				i++
			}
		}
	}
	return strings.Join(out, " ")
}

// iosConsoleList is the console's login list (D117): local only.
const iosConsoleList = "CONSOLE"

// aaaRank orders the lines of the aaa unit as D118 does, with 'aaa
// new-model' first: nothing under 'aaa' but 'aaa new-model' exists on IOS
// until it is set (the spike's "Legacy IOS 12.4": 'aaa group server' and its
// leaves pasted before it are rejected). (0) 'aaa new-model' (from here the
// vty lines use the default list), (1) the removal of the command
// authorization lists that name the group of an old server entry (D117,
// amended), (2) the removal of the group entries that name the old entry,
// (3) the removal of the old entry (a host line or a named block at the
// standard's address: IOS refuses a second entry with the same address and
// key), (4) the server block, (5) the group and its server leaf, (6) the
// source interface, (7) the login lists, (8) exec authorization, (9) an
// enable list (the standard renders none; an operator's template may), (10)
// accounting, (11) the session id, then what the section has
// besides. The line leaves are typed after roles, snmp and mgmt-acl (Plan
// moves them there, the console first) and the command-authorization lines
// last (lateAAA).
func aaaRank(l Line) int {
	t := l.Text
	switch {
	case len(l.Context) == 0 && t == "aaa new-model":
		return 0
	case l.Op == OpNo && len(l.Context) == 0 && (strings.HasPrefix(t, "aaa authorization commands ") || t == "aaa authorization config-commands"):
		return 1
	case l.Op == OpNo && len(l.Context) == 1 && strings.HasPrefix(l.Context[0], "aaa group server ") && strings.HasPrefix(t, "server "):
		return 2
	case l.Op == OpNo && len(l.Context) == 0 && (strings.HasPrefix(t, "tacacs-server host ") || strings.HasPrefix(t, "radius-server host ") ||
		strings.HasPrefix(t, "tacacs server ") || strings.HasPrefix(t, "radius server ")):
		// the old entry goes before the standard one is added: IOS refuses a
		// second server entry with the same address and key
		return 3
	case strings.HasPrefix(t, "tacacs-server host "), strings.HasPrefix(t, "radius-server host "),
		strings.HasPrefix(firstCtx(l), "tacacs server "), strings.HasPrefix(firstCtx(l), "radius server "):
		return 4
	case strings.HasPrefix(t, "aaa group server "), strings.HasPrefix(firstCtx(l), "aaa group server "):
		return 5
	case len(l.Context) == 0 && (strings.HasPrefix(t, "ip tacacs source-interface ") || strings.HasPrefix(t, "ip radius source-interface ")):
		return 6
	case strings.HasPrefix(t, "aaa authentication login "):
		return 7
	case strings.HasPrefix(t, "aaa authorization exec "):
		return 8
	case strings.HasPrefix(t, "aaa authentication enable "):
		return 9
	case strings.HasPrefix(t, "aaa accounting "):
		return 10
	case strings.HasPrefix(t, "aaa session-id "):
		return 11
	case strings.HasPrefix(t, "aaa authorization commands "):
		return 13
	case strings.HasPrefix(t, "aaa authorization config-commands"):
		return 14
	case strings.HasPrefix(firstCtx(l), "line "):
		// the lines that use the method lists come after the lists
		return 15
	}
	return 12
}

// isLoginLeafLine reports a forward line that types the login method of a
// console or vty line.
func isLoginLeafLine(l Line) bool {
	return l.Op == OpLine && len(l.Context) == 1 && isLoginLeafPath([]string{l.Context[0], l.Text})
}

// leafOrder orders the line leaves of a region: the console first, then the
// vty ranges by their first line (a stable sort keeps a range's own leaves in
// the order they were planned).
func leafOrder(l Line) int {
	kind, lo, _, ok := lineRange(firstCtx(l))
	switch {
	case !ok:
		return 1 << 20
	case kind == "con":
		return lo
	}
	return 1000 + lo
}

func firstCtx(l Line) string {
	if len(l.Context) > 0 {
		return l.Context[0]
	}
	return ""
}

// --- access lists ------------------------------------------------------------------

// aclRuns reduces entries to runs of one action, each a sorted set.
func aclRuns(entries []string) [][]string {
	var out [][]string
	last := ""
	for _, e := range entries {
		act, _, _ := strings.Cut(e, " ")
		if len(out) == 0 || act != last {
			out = append(out, nil)
			last = act
		}
		out[len(out)-1] = append(out[len(out)-1], e)
	}
	for _, r := range out {
		slices.Sort(r)
	}
	return out
}

// iosACLs plans the rendered access lists of a section. Entries are appended
// by IOS, so a new permit that has to stand before a later deny is added
// after the later entries are removed and re-added (a standard list ends in
// an implicit deny, so the window opens nothing). It returns the adds, the
// removals of extras (after the adds: new entries before 'no' entries), the
// removals that must come first, and the headers handled.
func (p *planner) iosACLs(name string, dev []string, o *secOut) (adds, nos, pre []Line, handled map[string]bool) {
	st := p.ios
	handled = map[string]bool{}
	var headers []string
	for _, e := range st.entries[name] {
		path := e.path()
		if len(path) == 2 && isACLHeader(path[0]) && !slices.Contains(headers, path[0]) {
			headers = append(headers, path[0])
		}
	}
	for _, h := range headers {
		var want []iosEntry
		for _, e := range st.entries[name] {
			if path := e.path(); len(path) == 2 && path[0] == h {
				want = append(want, e)
			}
		}
		var devEntries []string
		for _, s := range dev {
			if path := strings.Split(s, pathSep); len(path) == 2 && path[0] == h {
				devEntries = append(devEntries, path[1])
			}
		}
		// runs of one action: the rendered ones as indexes into want
		var wantIdx [][]int
		var wr [][]string
		last := ""
		for j, e := range want {
			act, _, _ := strings.Cut(e.path()[1], " ")
			if j == 0 || act != last {
				wantIdx = append(wantIdx, nil)
				wr = append(wr, nil)
				last = act
			}
			wantIdx[len(wantIdx)-1] = append(wantIdx[len(wantIdx)-1], j)
			wr[len(wr)-1] = append(wr[len(wr)-1], e.path()[1])
		}
		for _, r := range wr {
			slices.Sort(r)
		}
		dr := aclRuns(devEntries)
		equal := len(wr) == len(dr)
		for i := 0; equal && i < len(wr); i++ {
			equal = slices.Equal(wr[i], dr[i])
		}
		if equal {
			continue
		}
		handled[h] = true
		ctx := []string{h}
		undoNo := func(text string) []Line {
			if len(devEntries) == 0 {
				return []Line{{Op: OpNo, Text: h}}
			}
			return []Line{{Op: OpNo, Context: ctx, Text: text}}
		}
		retype := func(text string) []Line { return []Line{{Op: OpLine, Context: ctx, Text: text}} }

		// k: the first run that needs an entry typed
		k := -1
		for i := range wr {
			if i >= len(dr) {
				k = i
				break
			}
			if slices.ContainsFunc(wr[i], func(w string) bool { return !slices.Contains(dr[i], w) }) {
				k = i
				break
			}
		}
		removed := map[string]bool{}
		addsBefore := len(adds)
		if k >= 0 {
			for j := k + 1; j < len(dr); j++ {
				for _, e := range dr[j] {
					pre = append(pre, Line{Op: OpNo, Context: ctx, Text: e, Undo: retype(e)})
					removed[e] = true
				}
			}
			have := map[string]int{}
			if k < len(dr) {
				for _, e := range dr[k] {
					have[e]++
				}
			}
			for i := k; i < len(wantIdx); i++ {
				for _, j := range wantIdx[i] {
					e := want[j]
					text := e.path()[1]
					if i == k && have[text] > 0 {
						have[text]--
						continue
					}
					adds = append(adds, Line{Op: OpLine, Context: ctx, Text: e.leaf, Undo: undoNo(text)})
				}
			}
		}
		// DECISION: IOS appends a typed entry, so a new permit that must stand
		// before a later deny is typed after the later entries are removed and
		// typed again (a standard list ends in an implicit deny: no window
		// opens). The device's extras are removed after the new entries (D106:
		// new before no) except one that is typed again, which goes first (a
		// list has no duplicates: a later no would take the new entry too).
		// extras: device entries that the rendered run at their place lacks;
		// one that is typed again is removed first (a list has no
		// duplicates: a later 'no' would take the new entry too)
		retyped := map[string]bool{}
		for _, a := range adds[addsBefore:] {
			retyped[norm(a.Undo[0].Text)] = true
		}
		for j, r := range dr {
			for _, e := range r {
				inPlace := j < len(wr) && slices.Contains(wr[j], e) && (k < 0 || j <= k)
				if inPlace || removed[e] {
					continue
				}
				if retyped[e] {
					pre = append(pre, Line{Op: OpNo, Context: ctx, Text: e, Undo: retype(e)})
					continue
				}
				nos = append(nos, Line{Op: OpNo, Context: ctx, Text: e, Undo: retype(e)})
				if !p.inPlain(name, h+pathSep+e) {
					o.inherited = append(o.inherited, h+pathSep+e)
				}
			}
		}
		if isNumberedACL(h) {
			o.warnings = append(o.warnings, "access list "+h+" is numbered: entries are appended; check the order by hand")
		}
	}
	return adds, nos, pre, handled
}

func isNumberedACL(h string) bool {
	f := strings.Fields(h)
	_, err := strconv.Atoi(f[len(f)-1])
	return err == nil
}

// localPriv15 reads whether the pulled device has a local user at privilege
// 15: the breakglass section of the extraction holds the 'username' lines
// (their secret elided). known is false when the extraction has no such
// section at all (a record that does not say).
func localPriv15(ex devconf.Extracted) (has, known bool) {
	sec, ok := ex.Sections[devconf.SectionBreakGlass]
	if !ok {
		return false, false
	}
	for _, s := range sec.Lines {
		f := strings.Fields(s)
		if len(f) < 2 || f[0] != "username" {
			continue
		}
		for i := 2; i+1 < len(f); i++ {
			if f[i] == "privilege" && f[i+1] == "15" {
				return true, true
			}
		}
	}
	return false, true
}

// iosFromCheck applies D106's access-class guard: a warning without --from,
// a refusal when --from is not permitted by the rendered ACL.
func (p *planner) iosFromCheck() (string, bool) {
	bound := false
	for _, s := range p.cur.Sections["mgmt-acl"].Lines {
		path := strings.Split(s, pathSep)
		if isBinding(path) {
			f := strings.Fields(path[len(path)-1])
			if len(f) >= 2 && p.ios.acls["ip access-list standard "+f[1]] {
				bound = true
			}
		}
	}
	if !bound {
		return "", false
	}
	if p.opt.From == "" {
		return "the management ACL is bound to the vty lines with access-class and --from was not given: check that the address you are logged in from is permitted before you paste (--from <address> makes tacctl check)", true
	}
	from, err := netip.ParseAddr(p.opt.From)
	if err != nil {
		return "--from " + p.opt.From + " is not an address", false
	}
	if from.Is6() && !from.Is4In6() {
		return "--from " + p.opt.From + " is an IPv6 address and the management ACL is a standard IPv4 list: not checked; make sure you reach the device from an address it permits", true
	}
	heads := make([]string, 0, len(p.ios.acls))
	for h := range p.ios.acls {
		heads = append(heads, h)
	}
	slices.Sort(heads)
	for _, h := range heads {
		for _, e := range p.ios.entries["mgmt-acl"] {
			path := e.path()
			if len(path) != 2 || path[0] != h {
				continue
			}
			if m, act := aclEntryMatch(path[1], from); m {
				if act == "permit" {
					return "", false
				}
				return "the management ACL is bound to the vty lines and " + p.opt.From + " is denied by the rendered ACL: pasting it could cut you off", false
			}
		}
	}
	return "the management ACL is bound to the vty lines and " + p.opt.From + " is not permitted by the rendered ACL: pasting it could cut you off", false
}

// aclEntryMatch matches a standard ACL entry ('permit 192.0.2.0 0.0.0.255',
// 'deny any log') against an address.
func aclEntryMatch(entry string, a netip.Addr) (bool, string) {
	f := strings.Fields(entry)
	if len(f) < 2 {
		return false, ""
	}
	act := f[0]
	if f[1] == "host" && len(f) >= 3 {
		// 'permit host A.B.C.D' is 'permit A.B.C.D' (wildcard 0.0.0.0)
		f = []string{f[0], f[2]}
	}
	if f[1] == "any" {
		return true, act
	}
	base, err := netip.ParseAddr(f[1])
	if err != nil || !a.Is4() || !base.Is4() {
		return false, act
	}
	wild := [4]byte{}
	if len(f) >= 3 {
		if w, err := netip.ParseAddr(f[2]); err == nil && w.Is4() {
			wild = w.As4()
		}
	}
	b, x := base.As4(), a.As4()
	for i := range b {
		if b[i]&^wild[i] != x[i]&^wild[i] {
			return false, act
		}
	}
	return true, act
}

// linesKnown reports whether every line a 'line vty A B' / 'line con N'
// header covers is one the device shows, in any section of the extraction (a
// login leaf, an access class, the implicit default).
func (p *planner) linesKnown(header string) bool {
	kind, lo, hi, ok := lineRange(header)
	if !ok {
		return false
	}
	if kind == "con" && lo == 0 && hi == 0 {
		return true // the console is there, whatever the record says
	}
	seen := map[int]bool{}
	for _, sec := range p.cur.Sections {
		for _, s := range sec.Lines {
			h, _, _ := strings.Cut(s, pathSep)
			k, a, b, ok := lineRange(h)
			if !ok || k != kind {
				continue
			}
			for l := a; l <= b; l++ {
				seen[l] = true
			}
		}
	}
	for l := lo; l <= hi; l++ {
		if !seen[l] {
			return false
		}
	}
	return true
}

// lateAAA reports the lines of the aaa unit that switch command
// authorization on: 'aaa authorization commands <level> default ...' and
// 'aaa authorization config-commands'. The block types them after every
// other line (HIGH 5: with a server that answers FAIL for the pasting user,
// each command typed after them is denied, the back-out's too).
func lateAAA(l Line) bool {
	if l.Op != OpLine || len(l.Context) != 0 {
		return false
	}
	return strings.HasPrefix(l.Text, "aaa authorization commands ") || l.Text == "aaa authorization config-commands"
}

// --- command authorization and the proven server (D117, D118) -----------------------

// cmdAuthHeldText is what the report says about the command-authorization
// lines a plan holds back (D118 (12)). It is the Action of their items.
const cmdAuthHeldText = "command authorization is not in this paste: log in on a new session with your own account and check 'show privilege', then plan again; it is the one group of lines left"

// cmdAuthWithheldPrefix marks a Delta.Withheld entry as a held-back
// command-authorization statement.
const cmdAuthWithheldPrefix = "command authorization, held back until the server is proven: "

// isCmdAuthStem reports a compared statement that switches command
// authorization on: 'aaa authorization commands <level> ...' and 'aaa
// authorization config-commands'.
func isCmdAuthStem(stem string) bool {
	return strings.HasPrefix(stem, "aaa authorization commands ") || stem == "aaa authorization config-commands"
}

// serverProven reports whether the pulled configuration already uses the
// scope's server, so command authorization may be typed in the same paste
// (D118 (12)): the server's address is in a 'tacacs server' block or a
// 'tacacs-server host' entry AND an 'aaa authentication login' or 'aaa
// authorization exec' method list names a group; or the device already has
// an 'aaa authorization commands' line (the server is in use by definition).
//
// The session that pastes was opened before AAA, as a local user the server
// does not know: once the commands list names the server every command of
// that session and of its back-out is asked of the server, which answers
// FAIL for an unknown name and never falls through. A device whose TACACS+
// path has not been proven can end with no session able to run a command.
func (p *planner) serverProven() bool {
	if slices.ContainsFunc(p.cur.Sections["aaa"].Lines, func(s string) bool { return strings.HasPrefix(s, "aaa authorization commands ") }) {
		return true
	}
	return p.serverInUse()
}
