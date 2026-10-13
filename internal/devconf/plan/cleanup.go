package plan

// The cleanup region of --converge (plan D111): a second, separately
// delimited region that removes the extras the first region leaves, pasted
// only after the first is verified. It is built from the extras of the plan
// (Delta.Extras, each with its exact removal line) under a closed allowlist
// of what D111 lets a cleanup remove, and under the hard guards of D111:
//
//   - never a line that holds the address of --from, and without --from
//     never a client-list entry (the person's own source could be in it);
//   - never while the standard's server is missing and the plan does not
//     bring it (the cleanup is refused as a whole);
//   - never in a section the pull's login could not see completely, nor in
//     one the plan did not plan;
//   - never anything the standard or the session depends on: not the
//     rendered server block or group, not the 'default' and 'CONSOLE'
//     lists, not a line, a login, the enable secret.
//
//   - never a server or group that a statement staying on the device names,
//     never the other protocol's servers and groups (802.1X), never a named
//     command authorization list (the pull does not say which line uses it).
//
// One output, one region: the cleanup is produced only for a device whose
// first region is empty (nothing left to paste: a re-plan after the verifying
// pull). A technician who copies a whole output would otherwise run both
// regions, and on Junos the second 'commit check' would confirm the first
// region's pending 'commit confirmed' unverified. With a first region the
// plan says only that the cleanup comes after it (Cleanup.Deferred).
//
// The first region is unchanged by it: the cleanup is its own list of
// lines, with its own banners (CleanupRegion), and Plan without
// Options.Converge makes none.

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// CleanupLeft is an extra the cleanup does not remove, with the reason.
type CleanupLeft struct {
	Section string `json:"section"`
	Text    string `json:"text"`
	Why     string `json:"why"`
}

// Cleanup is the second region of --converge.
type Cleanup struct {
	// Lines are the removals, in paste order. For a Junos device they are
	// 'delete' lines, for IOS 'no' lines under their submode header.
	Lines []Line
	// Sections hold the label of each section's removals (Why).
	Sections []SectionPlan
	// Whole is the reason the cleanup is refused as a whole (empty when it
	// is offered or when there is nothing to remove).
	Whole string
	// Left are the extras the cleanup does not remove, each with why.
	Left []CleanupLeft
	// Deferred is set when the device has a first region: the cleanup is not
	// made beside it (CleanupDeferred says what to do).
	Deferred string
	// extras maps a line of Lines to the extras (indexes into Delta.Extras)
	// it removes.
	extras [][]int
}

// Empty reports whether the cleanup has no line.
func (c Cleanup) Empty() bool { return len(c.Lines) == 0 }

// cleanupKindWhy is the reason of an extra that is not one of the kinds
// D111 lets the cleanup remove: its item keeps the removal line it always
// had (the person may type it), and the cleanup does not repeat it.
const cleanupKindWhy = "the cleanup does not remove this kind of statement"

// cleanupCmdListWhy is the reason of a named command authorization list: the
// extractor reads which login list a line uses, not which command list, so a
// list in use cannot be told from one that is not.
const cleanupCmdListWhy = "a named command authorization list may be in use on a line, and the pull does not say which: type the removal yourself when you know it is not"

// junosPendingCheck is the check a Junos cleanup region asks for besides the
// pull: the check pull of the first region is taken before its 'commit', and
// a plan made from that pull reads as applied while the 'commit confirmed'
// may still be pending (it would be rolled back when its time runs out).
const junosPendingCheck = "that 'show system commit' shows no pending 'commit confirmed' (type the plan's 'commit' first)"

// CleanupDeferred is the one report line of a device that has a first
// region: the cleanup is a second output, after it.
const CleanupDeferred = "cleanup comes after this region is pasted and verified: pull the device, then plan --converge again"

// cleanupWhy is the label above one section's removals.
func cleanupWhy(vendor, section string) string {
	switch section {
	case "aaa":
		if vendor == devconf.FamilyJunos {
			return "removes the servers the standard does not have"
		}
		return "removes the servers and groups the standard does not have"
	case "snmp":
		return "removes the SNMP communities and clients the standard does not have"
	case "roles":
		return "removes the login classes the standard does not have"
	}
	return "removes the entries the standard does not have"
}

// cleanupIsServerStatement reports whether a compared statement is part of
// the AAA server the device depends on.
func cleanupIsServerStatement(vendor, stem string) bool {
	if vendor == devconf.FamilyJunos {
		t := splitTokens(strings.TrimPrefix(stem, "set "))
		return len(t) >= 3 && t[0] == "system" && (t[1] == "tacplus-server" || t[1] == "radius-server")
	}
	path := strings.Split(stem, pathSep)
	head := path[0]
	for _, pfx := range []string{"tacacs server ", "radius server ", "aaa group server ", "tacacs-server host ", "radius-server host "} {
		if strings.HasPrefix(head, pfx) {
			return true
		}
	}
	return false
}

// buildCleanup fills d.Cleanup (--converge) and rewrites the actions of the
// items it answers. It runs after buildExtras and buildItems.
func (p *planner) buildCleanup(d *Delta) {
	d.Converge = true
	c := &d.Cleanup
	from := parseFrom(p.opt.From)

	// One output, one region: with a first region to paste there is no
	// cleanup beside it. The extras keep their removal lines outside any
	// region (the items), and the plan after the verifying pull offers the
	// cleanup.
	if !d.Empty() {
		c.Deferred = CleanupDeferred
		return
	}

	// the sections the cleanup may touch at all
	secWhy := map[string]string{}
	for _, name := range PlanOrder(d.Vendor) {
		sp := d.Of(name)
		switch sp.State {
		case StateNotSelected:
			secWhy[name] = "the section is not selected (--section)"
		case StateNA:
			secWhy[name] = "the standard has nothing for this section"
		case StateSkipped:
			secWhy[name] = "this paste does not plan the section: " + firstSentence(sp.Why)
		case StateNotVisible:
			secWhy[name] = "the pull's login could not see what the section holds"
		}
	}
	for _, it := range d.Items {
		if it.Kind == KindSecret && secWhy[it.Section] == "" {
			secWhy[it.Section] = "the pull's login could not see every statement of the section (a secret is not visible to it)"
		}
	}
	// the standard's server must be in place, or be put there by the first
	// region: a server statement the plan cannot fix refuses the cleanup
	whole := ""
	if sp := d.Of("aaa"); sp.State == StateSkipped {
		whole = "the aaa section is not planned (" + firstSentence(sp.Why) + "), so the standard's server is not in place and this paste does not put it there"
	}
	for _, it := range d.Items {
		if whole != "" {
			break
		}
		if it.Section == "aaa" && !it.Fixed && (it.Kind == KindMissing || it.Kind == KindDifferent) &&
			cleanupIsServerStatement(d.Vendor, strings.TrimPrefix(it.Statement, "e.g. ")) {
			whole = "the standard's server is missing and this paste does not put it there (" + it.Words + ")"
		}
	}
	if whole != "" {
		c.Whole = whole
		for _, e := range d.Extras {
			if len(e.Remove) > 0 && e.Guard == "" {
				c.Left = append(c.Left, CleanupLeft{e.Section, e.Text, whole})
			}
		}
		return
	}

	// the IOS cleanup knows the scope's protocol and what stays on the device
	var ic *iosCleanupCtx
	if d.Vendor == devconf.FamilyIOS {
		ic = p.iosCleanupContext(d)
	}

	type verdict struct {
		ok  bool
		why string
	}
	vs := make([]verdict, len(d.Extras))
	for i, e := range d.Extras {
		switch {
		case e.Guard != "":
			// the report already says why: nothing to add
			vs[i] = verdict{false, e.Guard}
		case len(e.Remove) == 0:
			vs[i] = verdict{false, "tacctl has no line that removes it"}
		case secWhy[e.Section] != "":
			vs[i] = verdict{false, secWhy[e.Section]}
		default:
			ok, why := p.cleanupAllowed(d, e, from, ic)
			vs[i] = verdict{ok, why}
		}
	}

	// One removal line may answer several extras (the leaves of one server
	// or group): it is offered only when every one of them passes.
	type slot struct {
		line   Line
		extras []int
		bad    string
	}
	var slots []*slot
	byKey := map[string]*slot{}
	for i, e := range d.Extras {
		if e.Guard != "" || len(e.Remove) == 0 {
			continue
		}
		for _, r := range e.Remove {
			k := removalKey(r)
			s := byKey[k]
			if s == nil {
				r.Section = e.Section
				s = &slot{line: r}
				byKey[k] = s
				slots = append(slots, s)
			}
			s.extras = append(s.extras, i)
		}
	}

	// The dependencies, until nothing changes: a server leaf under the
	// standard's group goes only with the block or host it names; a server
	// stays while a group entry that names it stays (a group that a staying
	// statement names keeps its entries); and a removal line goes only when
	// every extra it answers does.
	for changed := true; changed; {
		changed = false
		down := func(i int, why string) {
			if vs[i].ok {
				vs[i] = verdict{false, why}
				changed = true
			}
		}
		if ic != nil {
			var removed, stays []string
			for i, e := range d.Extras {
				if vs[i].ok && len(e.Remove) == 1 && len(e.Remove[0].Context) == 0 {
					removed = append(removed, e.Remove[0].Text)
				}
			}
			for i, e := range d.Extras {
				if e.Section != "aaa" {
					continue
				}
				path := strings.Split(e.Text, pathSep)
				if len(path) == 2 && !vs[i].ok {
					if k := iosGroupEntryServer(path[0], path[1]); k != "" {
						stays = append(stays, k)
					}
				}
				if !vs[i].ok {
					continue
				}
				for _, r := range e.Remove {
					if len(r.Context) == 1 && strings.HasPrefix(r.Context[0], "aaa group server ") {
						k := iosGroupEntryServer(r.Context[0], r.Text)
						if !slices.ContainsFunc(removed, func(s string) bool { return sameServerEntry(s, k) }) {
							down(i, "it names a server that stays: the group is left as it is")
						}
					}
				}
			}
			for i, e := range d.Extras {
				if vs[i].ok && len(e.Remove) == 1 && len(e.Remove[0].Context) == 0 &&
					slices.ContainsFunc(stays, func(s string) bool { return sameServerEntry(s, e.Remove[0].Text) }) {
					down(i, "a group entry that names it stays")
				}
			}
		}
		for _, s := range slots {
			s.bad = ""
			for _, i := range s.extras {
				if !vs[i].ok {
					s.bad = vs[i].why
					break
				}
			}
			if s.bad == "" {
				continue
			}
			for _, i := range s.extras {
				down(i, "the same line also removes a statement the cleanup keeps ("+s.bad+")")
			}
		}
	}

	// order: sections as PlanOrder; within a section the leaves under a
	// header first, then the groups, then the servers (a group's entry goes
	// before the group, the group before the server it names)
	for _, name := range PlanOrder(d.Vendor) {
		var ss []*slot
		for _, s := range slots {
			if s.bad == "" && s.line.Section == name {
				ss = append(ss, s)
			}
		}
		slices.SortStableFunc(ss, func(a, b *slot) int { return cleanupRank(a.line) - cleanupRank(b.line) })
		if len(ss) == 0 {
			continue
		}
		c.Sections = append(c.Sections, SectionPlan{Name: name, State: StatePlanned, Why: cleanupWhy(d.Vendor, name), Statements: len(ss)})
		for _, s := range ss {
			c.Lines = append(c.Lines, s.line)
			c.extras = append(c.extras, s.extras)
		}
	}
	for i, e := range d.Extras {
		if e.Guard != "" || len(e.Remove) == 0 || vs[i].ok {
			continue
		}
		c.Left = append(c.Left, CleanupLeft{e.Section, e.Text, vs[i].why})
	}

	// the items: what the cleanup does about each extra they name
	if len(c.Lines) > 0 {
		cd := cleanupDelta(*d)
		lineNo := map[int]int{}
		for n, rl := range RegionLines(cd, Header{}, Wrapper{}) {
			if rl.Line >= 0 {
				lineNo[rl.Line] = n + 1
			}
		}
		extraLines := map[int][]int{}
		for li, es := range c.extras {
			for _, ei := range es {
				extraLines[ei] = append(extraLines[ei], lineNo[li])
			}
		}
		for i := range d.Items {
			it := &d.Items[i]
			if it.Kind != KindExtra || it.Fixed {
				continue
			}
			var ns []int
			for _, ei := range p.extrasOfItem(d, *it) {
				ns = append(ns, extraLines[ei]...)
			}
			if len(ns) > 0 {
				it.Action = "Removed by the cleanup region, " + lineNumbers(ns) + "."
			}
		}
	}
	for i := range d.Items {
		it := &d.Items[i]
		if it.Kind != KindExtra || it.Fixed || strings.HasPrefix(it.Action, "Removed by the cleanup region") {
			continue
		}
		for _, ei := range p.extrasOfItem(d, *it) {
			if why := cleanupLeftWhy(c.Left, d.Extras[ei]); why != "" && why != cleanupKindWhy && !strings.Contains(it.Action, "(") {
				it.Action = strings.TrimSuffix(it.Action, ".") + ". Not in the cleanup: " + why + "."
				break
			}
		}
	}
}

func cleanupLeftWhy(left []CleanupLeft, e Extra) string {
	for _, l := range left {
		if l.Section == e.Section && l.Text == e.Text {
			return l.Why
		}
	}
	return ""
}

// extrasOfItem are the extras (indexes into d.Extras) an extra item stands
// for: its own statement, or every extra of the object a grouped item
// folded.
func (p *planner) extrasOfItem(d *Delta, it Item) []int {
	stem := strings.TrimPrefix(it.Statement, "e.g. ")
	obj, _ := objectOf(d.Vendor, stem, p.blk)
	var out []int
	for i, e := range d.Extras {
		if e.Section != it.Section {
			continue
		}
		// a secret statement's item shows the place of its value
		if e.Text == stem || shownSecret(e.Text) == stem {
			out = append(out, i)
			continue
		}
		if strings.HasPrefix(it.Statement, "e.g. ") && obj != "" {
			if eo, _ := objectOf(d.Vendor, e.Text, p.blk); eo == obj {
				out = append(out, i)
			}
		}
	}
	return out
}

// removalKey identifies a removal line (so the leaves of one object share
// one).
func removalKey(l Line) string {
	return strings.Join(l.Context, "\x00") + "\x01" + string(l.Op) + "\x01" + l.Text
}

// iosGroupEntryServer maps a group's server leaf ('server name OLD', 'server
// 192.0.2.5') under the group's header ('aaa group server tacacs+ G') to the
// removal line of the block or host it names, by the group's protocol: a
// RADIUS group's 'server name X' is 'radius server X', never a TACACS+ one.
// "" for a leaf it does not know.
func iosGroupEntryServer(header, leaf string) string {
	hf := strings.Fields(header)
	if len(hf) < 5 || hf[0] != "aaa" || hf[1] != "group" || hf[2] != "server" {
		return ""
	}
	block, host := "tacacs server ", "tacacs-server"
	switch hf[3] {
	case "tacacs+":
	case "radius", "radius-server":
		block, host = "radius server ", "radius-server"
	default:
		return ""
	}
	f := strings.Fields(leaf)
	switch {
	case len(f) == 3 && f[0] == "server" && f[1] == "name":
		return block + f[2]
	case len(f) >= 2 && f[0] == "server":
		return hostEntry(append([]string{host, "host"}, f[1:]...))
	}
	return ""
}

// sameServerEntry reports whether two removal lines name one server: the same
// line, or two host lines of one protocol at one address whose ports do not
// differ (a group entry 'server 192.0.2.5' names the host the device stores
// as 'radius-server host 192.0.2.5 auth-port 1812 acct-port 1813').
func sameServerEntry(a, b string) bool {
	if a == b {
		return true
	}
	fa, fb := strings.Fields(a), strings.Fields(b)
	if len(fa) >= 3 && len(fb) >= 3 && fa[0] == fb[0] && fa[1] == "host" && fb[1] == "host" && fa[2] == fb[2] &&
		(fa[0] == "tacacs-server" || fa[0] == "radius-server") {
		return samePorts(fa[3:], fb[3:])
	}
	return false
}

// cleanupRank orders the removals of a section: the entries under a header
// first, then the groups, then the servers (and the rest), so that a group
// is gone before the server it names and an entry before its group.
func cleanupRank(l Line) int {
	switch {
	case len(l.Context) > 0:
		return 0
	case strings.HasPrefix(l.Text, "aaa group server "):
		return 1
	case strings.HasPrefix(l.Text, "tacacs server "), strings.HasPrefix(l.Text, "radius server "),
		strings.HasPrefix(l.Text, "tacacs-server host "), strings.HasPrefix(l.Text, "radius-server host "):
		return 2
	}
	return 3
}

// iosCleanupCtx is what the IOS cleanup needs to know of the device beyond
// the extra itself: the scope's protocol and what the statements that stay
// name.
type iosCleanupCtx struct {
	// proto is the scope's protocol: "tacacs" or "radius". Only its own
	// servers and groups are ever removed: the other protocol's may serve
	// 802.1X or a list of another purpose.
	proto string
	// groups maps a group name to a statement that stays and names it.
	groups map[string]string
	// every is a statement that stays and uses every server of the scope's
	// protocol ('group tacacs+', 'group radius'), or "".
	every string
}

// scopeProtocol is the protocol of the scope's rendering: "radius" when its
// aaa section has a RADIUS server or group (on Junos: a radius-server or the
// radius accounting destination), else "tacacs".
func (p *planner) scopeProtocol() string {
	for _, s := range p.exp {
		if s.Name != "aaa" {
			continue
		}
		for _, l := range s.Lines {
			if strings.HasPrefix(l, "radius server ") || strings.HasPrefix(l, "radius-server host ") ||
				strings.HasPrefix(l, "aaa group server radius ") ||
				strings.HasPrefix(l, "set system radius-server ") || l == "set system accounting destination radius" {
				return "radius"
			}
		}
	}
	return "tacacs"
}

// iosCleanupContext reads, from every aaa statement the device keeps (the
// pulled lines: the cleanup removes no list), the groups they name.
func (p *planner) iosCleanupContext(d *Delta) *iosCleanupCtx {
	c := &iosCleanupCtx{proto: p.scopeProtocol(), groups: map[string]string{}}
	keyword := "tacacs+"
	if c.proto == "radius" {
		keyword = "radius"
	}
	lines := slices.Clone(p.cur.Sections["aaa"].Lines)
	for _, w := range d.Withheld {
		lines = append(lines, strings.TrimPrefix(w, cmdAuthWithheldPrefix))
	}
	for _, k := range d.Kept {
		if k.Section == "aaa" {
			lines = append(lines, k.Text)
		}
	}
	for _, l := range lines {
		head := strings.Split(l, pathSep)[0]
		if !strings.HasPrefix(head, "aaa ") || strings.HasPrefix(head, "aaa group server ") {
			continue
		}
		f := strings.Fields(head)
		for i := 0; i+1 < len(f); i++ {
			if f[i] != "group" {
				continue
			}
			if f[i+1] == keyword {
				if c.every == "" {
					c.every = head
				}
				continue
			}
			if _, ok := c.groups[f[i+1]]; !ok {
				c.groups[f[i+1]] = head
			}
		}
	}
	return c
}

// parseFrom reads --from (an address, with or without a prefix length).
func parseFrom(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// holdsAddr reports whether a word of text is the address or a prefix that
// contains it.
func holdsAddr(text string, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '[' || r == ']' }) {
		if pf, err := netip.ParsePrefix(w); err == nil && pf.Contains(a) {
			return true
		}
		if ad, err := netip.ParseAddr(w); err == nil && ad.Unmap() == a {
			return true
		}
	}
	return false
}

// cleanupAllowed applies the closed allowlist of D111 and the guards of the
// sources to one extra.
func (p *planner) cleanupAllowed(d *Delta, e Extra, from netip.Addr, ic *iosCleanupCtx) (bool, string) {
	for _, r := range e.Remove {
		if holdsAddr(r.Text, from) || holdsAddr(e.Text, from) {
			return false, "it holds the address you are logged in from (--from)"
		}
		if d.Vendor == devconf.FamilyJunos {
			if ok, why := p.junosCleanupAllowed(r, e, from); !ok {
				return false, why
			}
			continue
		}
		if ok, why := ic.allowed(r); !ok {
			return false, why
		}
	}
	return true, ""
}

func (p *planner) junosCleanupAllowed(r Line, e Extra, from netip.Addr) (bool, string) {
	if r.Op != OpDelete {
		return false, "the cleanup only deletes"
	}
	t := splitTokens(strings.TrimPrefix(r.Text, "delete "))
	switch {
	case len(t) == 3 && t[0] == "system" && (t[1] == "tacplus-server" || t[1] == "radius-server"):
		// the scope manages one protocol's servers only: the other's may serve
		// accounting or another login method, and is never removed; and a
		// server that a statement staying on the device names is left
		proto := protoWord(t[1])
		if proto != p.scopeProtocol() {
			other := "RADIUS"
			if proto == "tacacs" {
				other = "TACACS+"
			}
			return false, "it is a " + other + " server and the scope's protocol is the other: it may serve accounting or another login method, and is never removed"
		}
		if st := p.junosStayingNames(t[1], t[2]); st != "" {
			return false, "a statement that stays names it: " + st
		}
		return true, ""
	case len(t) == 3 && t[0] == "snmp" && t[1] == "community":
		return true, ""
	case len(t) >= 3 && t[0] == "snmp" && t[1] == "client-list":
		// a client list is a list of sources: the person's own could be in it
		if !from.IsValid() {
			return false, "a client-list entry could be your own source: give --from <your address> to remove it"
		}
		return true, ""
	case len(t) == 4 && t[0] == "system" && t[1] == "login" && t[2] == "class":
		return true, ""
	}
	return false, cleanupKindWhy
}

// junosStayingNames finds a statement of the device that stays (the cleanup
// removes no accounting statement) and names the server: 'system accounting
// destination <protocol> server <address> ...'. kind is the server's
// hierarchy ('tacplus-server', 'radius-server'). "" when none does.
func (p *planner) junosStayingNames(kind, addr string) string {
	dest := map[string]string{"tacplus-server": "tacplus", "radius-server": "radius"}[kind]
	for _, s := range p.cur.Sections["aaa"].Lines {
		t := splitTokens(strings.TrimPrefix(s, "set "))
		if len(t) >= 6 && t[0] == "system" && t[1] == "accounting" && t[2] == "destination" && t[3] == dest && t[4] == "server" && t[5] == addr {
			return strings.TrimPrefix(s, "set ")
		}
	}
	return ""
}

// protoWord names the protocol of a keyword of a server line ('tacacs',
// 'tacacs+', 'radius'): "tacacs", "radius" or "".
func protoWord(w string) string {
	switch w {
	case "tacacs", "tacacs+", "tacacs-server", "tacplus-server":
		return "tacacs"
	case "radius", "radius-server":
		return "radius"
	}
	return ""
}

// allowed applies the closed allowlist of D111 (amended) to one removal
// line.
func (c *iosCleanupCtx) allowed(r Line) (bool, string) {
	if r.Op != OpNo {
		return false, "the cleanup only removes"
	}
	f := strings.Fields(r.Text)
	// own: the scope manages one protocol's servers and groups only
	own := func(proto string) (bool, string) {
		if proto == "" {
			return false, cleanupKindWhy
		}
		if proto != c.proto {
			other := "RADIUS"
			if proto == "tacacs" {
				other = "TACACS+"
			}
			return false, "it is a " + other + " entry and the scope's protocol is the other: it may serve 802.1X or another list, and is never removed"
		}
		return true, ""
	}
	server := func(proto string) (bool, string) {
		if ok, why := own(proto); !ok {
			return false, why
		}
		if c.every != "" {
			return false, "a statement that stays uses every server of the protocol: " + c.every
		}
		return true, ""
	}
	switch {
	case len(r.Context) == 0 && len(f) >= 3 && (f[0] == "tacacs-server" || f[0] == "radius-server") && f[1] == "host":
		return server(protoWord(f[0]))
	case len(r.Context) == 0 && len(f) == 3 && (f[0] == "tacacs" || f[0] == "radius") && f[1] == "server":
		return server(protoWord(f[0]))
	case len(r.Context) == 0 && len(f) >= 5 && f[0] == "aaa" && f[1] == "group" && f[2] == "server":
		if ok, why := own(protoWord(f[3])); !ok {
			return false, why
		}
		if st, named := c.groups[f[4]]; named {
			return false, "a statement that stays names this group: " + st
		}
		return true, ""
	case len(r.Context) == 1 && strings.HasPrefix(r.Context[0], "aaa group server ") &&
		(len(f) == 3 && f[0] == "server" && f[1] == "name" || len(f) >= 2 && f[0] == "server"):
		hf := strings.Fields(r.Context[0])
		if len(hf) < 5 {
			return false, cleanupKindWhy
		}
		return own(protoWord(hf[3]))
	case len(r.Context) == 0 && len(f) >= 2 && f[0] == "snmp-server" && f[1] == "community":
		return true, ""
	case len(r.Context) == 0 && len(f) >= 4 && f[0] == "aaa" && f[1] == "authorization" && f[2] == "commands":
		return false, cleanupCmdListWhy
	}
	return false, cleanupKindWhy
}

// cleanupDelta is the cleanup as a Delta of its own, so the region emitters
// of the plan make its region.
func cleanupDelta(d Delta) Delta {
	return Delta{Vendor: d.Vendor, Syntax: d.Syntax, Scope: d.Scope, Lines: d.Cleanup.Lines, Sections: d.Cleanup.Sections}
}

// --- the emitters ------------------------------------------------------------------------

// CleanupLines returns the lines between the cleanup's banners: the same
// wrapper as the plan's region, the removals, and the confirmed commit (or
// 'end') last. The whole-paste invariant holds for them as for the
// region's.
func CleanupLines(d Delta, h Header, w Wrapper) []RegionLine {
	if d.Cleanup.Empty() {
		return nil
	}
	if d.Vendor == devconf.FamilyWTI {
		return wtiCleanupLines(d, h)
	}
	cd := cleanupDelta(d)
	if d.Vendor == devconf.FamilyIOS {
		return iosRegion(cd)
	}
	return junosRegionWord(cd, h, w, "cleanup")
}

// cleanupFromBanner and cleanupToBanner are the cleanup's own banner pair
// (D108, amended): they are not the first region's, so a copy of an output
// that held both could not be told one from the other, and a banner search
// for 'PASTE TO HERE' never ends the cleanup.
func cleanupFromBanner(d Delta, h Header) string {
	if d.Vendor == devconf.FamilyWTI {
		return wtiBanner("DO THESE CLEANUP STEPS ON: " + h.Device)
	}
	bc := bannerChar(d.Vendor)
	return bc + " CLEANUP FROM HERE: " + h.Device + " " + bc
}

func cleanupToBanner(d Delta, h Header) string {
	if d.Vendor == devconf.FamilyWTI {
		return wtiBanner("END OF CLEANUP STEPS")
	}
	bc := bannerChar(d.Vendor)
	return bc + " CLEANUP TO HERE: " + h.Device + " " + bc
}

// CleanupRegion is the cleanup's banner pair and the lines between them
// ("" when there is none).
func CleanupRegion(d Delta, h Header, w Wrapper) string {
	if d.Cleanup.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString(cleanupFromBanner(d, h) + "\n")
	for _, l := range CleanupLines(d, h, w) {
		b.WriteString(l.Text + "\n")
	}
	b.WriteString(cleanupToBanner(d, h) + "\n")
	return b.String()
}

// CleanupPlain is the cleanup's statements only (the file for 'load set' on
// Junos), as Plain is for the first region.
func CleanupPlain(d Delta, h Header, w Wrapper) string {
	if d.Vendor == devconf.FamilyWTI {
		return ""
	}
	var b strings.Builder
	for _, l := range CleanupLines(d, h, w) {
		if !l.Comment && !l.Wrapper {
			b.WriteString(l.Text + "\n")
		}
	}
	return b.String()
}

// CleanupAfter is the text after the cleanup region: the check, the one
// line to type, and what undoes it. All comments.
func CleanupAfter(d Delta, h Header, w Wrapper) string {
	if d.Cleanup.Empty() {
		return ""
	}
	if d.Vendor == devconf.FamilyWTI {
		return wtiCleanupAfter(d, h)
	}
	var b strings.Builder
	c := commentLeader(d.Vendor)
	add := func(s string) {
		for _, l := range wrapText(s, 96) {
			b.WriteString(c + " " + l + "\n")
		}
	}
	// the cleanup is only ever made for a device with no first region
	// On Junos the check pull the plan asked for is taken before the one word
	// 'commit': a pull that reads ok does not say the confirmed commit is
	// done, and a pending one that runs out takes the first region back.
	pending := " "
	if d.Vendor == devconf.FamilyJunos {
		pending = ", " + junosPendingCheck + ", "
	}
	why := "There is no other paste for " + h.Device + ": its first region is empty. Check that the pull is current (tacctl device config pull " + h.Device +
		" --diff reads ok for aaa)" + pending + "and keep a NEW ssh session as yourself open."
	b.WriteString(c + "\n")
	add(why)
	if d.Vendor == devconf.FamilyIOS {
		// a comment line, never a plain one: a copy of the whole output must
		// not save before the check (as the first region's)
		b.WriteString("! Same check, then type this one command yourself:  write memory\n")
		add("Nothing rolls the cleanup back by itself; until write memory is typed a reload brings back the saved configuration. A removed server entry takes its key with it: tacctl holds no key it removes, so to put one back you type it again.")
		if d.restoreShown() {
			b.WriteString("!\n")
			add("Restore point: " + d.Restore.Name(h) + " (the block above the region).")
			restoreAlternative(d, h, "", add, func(s string) { b.WriteString("!   " + s + "\n") })
		}
		b.WriteString(lockoutHelp(d, h))
		return b.String()
	}
	n := strconv.Itoa(confirmMinutes(w))
	b.WriteString("# Same check, same one word, typed yourself:  commit     (before the " + n + " minutes end)\n")
	add("If any line printed \"error:\", do not type commit: the switch undoes the cleanup by itself in " + n + " minutes. To undo it after the commit: show system commit, then rollback <n> of the entry just before the one commented \"tacctl cleanup " + commentSafe(h.Device) + "\", then commit. A removed server's secret is not held by tacctl: type it again.")
	b.WriteString(lockoutHelp(d, h))
	return b.String()
}

// extrasStay says how many extras the cleanup leaves.
func extrasStay(n int) string {
	if n == 1 {
		return "1 extra stays: its item above says why."
	}
	return strconv.Itoa(n) + " extras stay: each item above says why."
}

// cleanupKinds names what the cleanup's lines remove, in the words of the
// report.
func cleanupKinds(c Cleanup) string {
	var kinds []string
	add := func(k string) {
		if !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	for _, l := range c.Lines {
		t := strings.TrimPrefix(l.Text, "delete ")
		switch {
		case strings.HasPrefix(t, "system tacplus-server"), strings.HasPrefix(t, "tacacs server"), strings.HasPrefix(t, "tacacs-server host"):
			add("TACACS+ servers")
		case strings.HasPrefix(t, "system radius-server"), strings.HasPrefix(t, "radius server"), strings.HasPrefix(t, "radius-server host"):
			add("RADIUS servers")
		case strings.HasPrefix(t, "aaa group server"), len(l.Context) > 0 && strings.HasPrefix(l.Context[0], "aaa group server"):
			add("server groups")
		case strings.HasPrefix(t, "snmp community"), strings.HasPrefix(t, "snmp-server community"):
			add("SNMP communities")
		case strings.HasPrefix(t, "snmp client-list"):
			add("SNMP clients")
		case strings.HasPrefix(t, "system login class"):
			add("login classes")
		default:
			add("other lines")
		}
	}
	return strings.Join(kinds, ", ")
}
