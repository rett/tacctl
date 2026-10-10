package plan

// The ownership tables (plan §4 for Junos, §4b for IOS; apply-deferred.md
// D79) and the class table, as data. A row names an object tacctl renders;
// what the planner may delete is decided by the row's Mode and by nothing
// else. Each row has a test (owned_test.go) and a row without one fails it.

import (
	"slices"
	"sort"
	"strings"
)

// Mode says how the planner treats the extras inside an object.
type Mode string

const (
	// ModeWhole: the object is rendered whole; every statement under it
	// that the rendering does not hold is deleted.
	ModeWhole Mode = "whole"
	// ModeLeaves: a list or group of leaves under the prefix; every extra
	// statement with the prefix is deleted when the rendering sets any.
	ModeLeaves Mode = "leaves"
	// ModeRenderedLeaves: under the named object only the leaf keywords the
	// rendering sets are owned; every other leaf is kept.
	ModeRenderedLeaves Mode = "rendered-leaves"
	// ModeList: an ordered list rendered whole: when it differs it is
	// rewritten as a delete directly followed by its set.
	ModeList Mode = "list"
	// ModeSingle: a single-valued leaf: the rendered set replaces the value
	// in place, the other value is never deleted; with no rendered value the
	// leaf is kept.
	ModeSingle Mode = "single"
)

// OwnedRow is one row of an ownership table.
type OwnedRow struct {
	// ID names the row in tests ('junos.roles.class').
	ID      string
	Section string
	// Pattern is the statement path prefix, space separated; '$' is the
	// object's name, which must be one the rendering sets at that position.
	Pattern string
	Mode    Mode
	// Why is what the block says above the section's lines about this
	// object (the section's why-line is built from the rows that fired).
	Why string
	// Kept says what is left alone inside the hierarchy (the table's
	// last column).
	Kept string
	// Ordered is set for an object whose element order matters.
	Ordered bool
	// Depth, when not 0, is the number of tokens of an owned statement: a
	// ModeLeaves row owns 'system accounting destination tacplus' (4) and
	// not 'system accounting destination tacplus server 192.0.2.8 ...'.
	Depth int
}

// junosOwned is the plan §4 table for Junos.
var junosOwned = []OwnedRow{
	{ID: "junos.roles.class", Section: "roles", Pattern: "system login class $", Mode: ModeWhole,
		Why:  "the login classes tacctl renders (every leaf of a rendered class, allow-*/deny-* included)",
		Kept: "every other class; a template user's uid and authentication leaves"},
	{ID: "junos.roles.user-class", Section: "roles", Pattern: "system login user $ class", Mode: ModeSingle,
		Why:  "the class of the template users",
		Kept: "every other user"},

	{ID: "junos.aaa.order", Section: "aaa", Pattern: "system authentication-order", Mode: ModeList, Ordered: true,
		Why:  "the authentication order tacctl renders",
		Kept: ""},
	{ID: "junos.aaa.events", Section: "aaa", Pattern: "system accounting events", Mode: ModeLeaves, Depth: 4,
		Why:  "the accounting events tacctl renders",
		Kept: ""},
	{ID: "junos.aaa.destination", Section: "aaa", Pattern: "system accounting destination", Mode: ModeLeaves, Depth: 4,
		Why:  "the accounting destination tacctl renders",
		Kept: ""},
	{ID: "junos.aaa.tacplus", Section: "aaa", Pattern: "system tacplus-server $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's TACACS+ server",
		Kept: "another server; source-address, timeout, retry and every other leaf under tacctl's server; tacplus-options"},
	{ID: "junos.aaa.radius", Section: "aaa", Pattern: "system radius-server $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's RADIUS server",
		Kept: "another server; every other leaf under tacctl's server; radius-options"},

	{ID: "junos.snmp.client-list", Section: "snmp", Pattern: "snmp client-list $", Mode: ModeWhole,
		Why:  "the client list tacctl renders",
		Kept: "other client lists"},
	{ID: "junos.snmp.community", Section: "snmp", Pattern: "snmp community $", Mode: ModeWhole,
		Why:  "the community tacctl renders for the scope",
		Kept: "other communities"},
	{ID: "junos.snmp.v3-user", Section: "snmp", Pattern: "snmp v3 usm local-engine user $", Mode: ModeWhole,
		Why:  "the SNMPv3 user tacctl renders",
		Kept: "other v3 users"},
	{ID: "junos.snmp.v3-group", Section: "snmp", Pattern: "snmp v3 vacm security-to-group security-model usm security-name $", Mode: ModeWhole,
		Why:  "the SNMPv3 group mapping tacctl renders",
		Kept: ""},
	{ID: "junos.snmp.v3-access", Section: "snmp", Pattern: "snmp v3 vacm access group $", Mode: ModeWhole,
		Why:  "the SNMPv3 access tacctl renders",
		Kept: ""},
	{ID: "junos.snmp.view", Section: "snmp", Pattern: "snmp view $", Mode: ModeWhole,
		Why:  "the SNMP view tacctl renders",
		Kept: "other views"},
	{ID: "junos.snmp.location", Section: "snmp", Pattern: "snmp location", Mode: ModeSingle,
		Why: "the location tacctl renders", Kept: "the location when tacctl renders none"},
	{ID: "junos.snmp.contact", Section: "snmp", Pattern: "snmp contact", Mode: ModeSingle,
		Why: "the contact tacctl renders", Kept: "the contact when tacctl renders none"},
	{ID: "junos.snmp.description", Section: "snmp", Pattern: "snmp description", Mode: ModeSingle,
		Why: "the description tacctl renders", Kept: "the description when tacctl renders none"},

	{ID: "junos.mgmt-acl.filter", Section: "mgmt-acl", Pattern: "firewall family inet filter $", Mode: ModeWhole, Ordered: true,
		Why:  "the management filter tacctl renders (its terms, their leaves and their order)",
		Kept: "other filters; the lo0 application"},
}

// iosOwned is the plan §4b table for IOS.
var iosOwned = []OwnedRow{
	{ID: "ios.aaa.method-list", Section: "aaa", Pattern: "aaa <type> default", Mode: ModeSingle,
		Why:  "the method lists tacctl renders, each replaced by the rendered line",
		Kept: "a method list of another name"},
	{ID: "ios.aaa.commands-level", Section: "aaa", Pattern: "aaa (authorization|accounting) commands <level> default", Mode: ModeLeaves,
		Why:  "a commands list of a level tacctl does not render is removed",
		Kept: ""},
	{ID: "ios.aaa.config-commands", Section: "aaa", Pattern: "aaa authorization config-commands", Mode: ModeSingle,
		Why: "the configuration-command authorization tacctl renders", Kept: ""},
	{ID: "ios.aaa.server-block", Section: "aaa", Pattern: "tacacs server $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's server block",
		Kept: "another server block; other leaves under tacctl's server"},
	{ID: "ios.aaa.radius-block", Section: "aaa", Pattern: "radius server $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's RADIUS server block",
		Kept: "another server block; other leaves under tacctl's server"},
	{ID: "ios.aaa.legacy-host", Section: "aaa", Pattern: "tacacs-server host $", Mode: ModeSingle,
		Why:  "tacctl's server line, retyped as rendered",
		Kept: "another server"},
	{ID: "ios.aaa.group", Section: "aaa", Pattern: "aaa group server tacacs+ $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's server group",
		Kept: "another group"},
	{ID: "ios.aaa.radius-group", Section: "aaa", Pattern: "aaa group server radius $", Mode: ModeRenderedLeaves,
		Why:  "tacctl's RADIUS server group",
		Kept: "another group"},

	{ID: "ios.roles.privilege", Section: "roles", Pattern: "privilege exec level <level>", Mode: ModeWhole,
		Why:  "the privilege lines of the levels tacctl renders",
		Kept: "the parent lines IOS adds by itself; the lines of a level tacctl does not render"},

	{ID: "ios.snmp.community", Section: "snmp", Pattern: "snmp-server community $", Mode: ModeSingle,
		Why:  "the community tacctl renders, retyped as rendered",
		Kept: "other communities (their names are not compared)"},
	{ID: "ios.snmp.location", Section: "snmp", Pattern: "snmp-server location", Mode: ModeSingle,
		Why: "the location tacctl renders", Kept: "the location when tacctl renders none"},
	{ID: "ios.snmp.contact", Section: "snmp", Pattern: "snmp-server contact", Mode: ModeSingle,
		Why: "the contact tacctl renders", Kept: "the contact when tacctl renders none"},
	{ID: "ios.snmp.acl", Section: "snmp", Pattern: "ip access-list standard $", Mode: ModeWhole, Ordered: true,
		Why:  "the SNMP access list tacctl renders (its entries and their order)",
		Kept: "other access lists"},

	{ID: "ios.mgmt-acl.acl", Section: "mgmt-acl", Pattern: "ip access-list standard $", Mode: ModeWhole, Ordered: true,
		Why:  "the management access list tacctl renders (its entries and their order)",
		Kept: "other access lists; the access-class binding"},
}

// OwnedTable returns the ownership table of a vendor family.
func OwnedTable(family string) []OwnedRow {
	if family == "ios" {
		return iosOwned
	}
	return junosOwned
}

// neverRow is a statement the planner never emits, whatever flag is given
// (plan §1 non-goals, D97, D106).
type neverRow struct {
	ID     string
	Family string
	// Prefix is a statement text prefix ('set', 'delete' and 'no' words
	// stripped); a statement matches when it equals the prefix or starts
	// with the prefix and a space.
	Prefix string
	// Contains, when not empty, must also be in the statement.
	Contains string
}

// neverEmitted is the "never" list as data. Plan refuses to return a Delta
// with a line that matches (a defensive check: the sections they live in are
// not planned, and the rendering carries none of them as '-' lines).
var neverEmitted = []neverRow{
	{ID: "junos.netconf", Family: "junos", Prefix: "system services netconf"},
	{ID: "junos.ssh", Family: "junos", Prefix: "system services ssh"},
	{ID: "junos.root", Family: "junos", Prefix: "system root-authentication"},
	{ID: "junos.lo0", Family: "junos", Prefix: "interfaces lo0"},
	{ID: "junos.groups", Family: "junos", Prefix: "groups"},
	{ID: "junos.apply-groups", Family: "junos", Prefix: "apply-groups"},
	// a template user's class leaf is roles; an authentication leaf is the
	// break-glass step
	{ID: "junos.breakglass", Family: "junos", Prefix: "system login user", Contains: " authentication "},
	// a line header is never removed: 'no line vty 0 15' takes the lines the
	// back-out is typed on (handled in neverMatch, which sees the 'no')
	{ID: "ios.enable-secret", Family: "ios", Prefix: "enable secret"},
	{ID: "ios.enable-password", Family: "ios", Prefix: "enable password"},
	{ID: "ios.username", Family: "ios", Prefix: "username"},
	{ID: "ios.netconf-yang", Family: "ios", Prefix: "netconf-yang"},
	{ID: "ios.transport", Family: "ios", Prefix: "transport input"},
	{ID: "ios.ip-ssh", Family: "ios", Prefix: "ip ssh"},
}

// neverMatch reports whether a produced line is on the never list ('no aaa
// new-model' as a forward change is on it too).
func neverMatch(family string, l Line) (string, bool) {
	text := strings.TrimSpace(l.Text)
	if family == "junos" {
		for _, w := range []string{"set ", "delete ", "insert ", "deactivate ", "activate "} {
			if rest, ok := strings.CutPrefix(text, w); ok {
				text = rest
				break
			}
		}
	} else if l.Op == OpNo && len(l.Context) == 0 {
		switch {
		case text == "aaa new-model":
			return "ios.no-aaa-new-model", true
		case strings.HasPrefix(text, "line "):
			return "ios.no-line", true
		}
	}
	for _, r := range neverEmitted {
		if r.Family != family {
			continue
		}
		if (text == r.Prefix || strings.HasPrefix(text, r.Prefix+" ")) && strings.Contains(" "+text+" ", r.Contains) {
			return r.ID, true
		}
	}
	return "", false
}

// --- the class table ------------------------------------------------------------

// Class is the login class the person pastes under. Permissions are its
// permission bits ('view', 'system-control', ...). A nil Class means the
// caller did not say: every section is planned.
type Class struct {
	Name        string
	Permissions []string
}

// ClassRule maps a statement prefix to the permission bits it needs. [S: lab
// check L1, observed on one class] On the lab switch an EN-CLASS login (the
// bits of devices' engineerBits) could load and 'commit check' a firewall
// filter and re-set 'system authentication-order', and answered 'syntax
// error' (the node is hidden from the class) to 'system tacplus-server',
// 'system accounting', 'system login' and 'snmp'. The bits below are the ones
// the Junos reference names; the hidden nodes of the observed class are the
// rows it lacks a bit of ([A] for which bit hides which node: only the
// outcome was observed).
type ClassRule struct {
	// Prefix is a statement path prefix, space separated.
	Prefix  string
	Section string
	// Bits are all required.
	Bits []string
	// Observed is what the lab check saw for EN-CLASS: "visible", "hidden".
	Observed string
}

// classRules is the data: longest prefix wins.
var classRules = []ClassRule{
	{Prefix: "system authentication-order", Section: "aaa", Bits: []string{"system-control"}, Observed: "visible"},
	{Prefix: "system tacplus-server", Section: "aaa", Bits: []string{"admin-control", "secret-control"}, Observed: "hidden"},
	{Prefix: "system radius-server", Section: "aaa", Bits: []string{"admin-control", "secret-control"}, Observed: "hidden"},
	{Prefix: "system accounting", Section: "aaa", Bits: []string{"admin-control"}, Observed: "hidden"},
	{Prefix: "system login", Section: "roles", Bits: []string{"admin-control"}, Observed: "hidden"},
	{Prefix: "snmp", Section: "snmp", Bits: []string{"snmp-control"}, Observed: "hidden"},
	{Prefix: "firewall", Section: "mgmt-acl", Bits: []string{"firewall-control"}, Observed: "visible"},
}

// ClassRules returns the class table.
func ClassRules() []ClassRule { return slices.Clone(classRules) }

// Needs returns the permission bits a section needs on Junos, the union of
// its class rows (the section-to-bits map of apply-deferred.md D87, as the
// lab check L1 corrected it).
func Needs(section string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range classRules {
		if r.Section != section {
			continue
		}
		for _, b := range r.Bits {
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	sort.Strings(out)
	return out
}

// classRuleFor returns the longest class row whose prefix the path starts
// with.
func classRuleFor(path []string) (ClassRule, bool) {
	best := -1
	var out ClassRule
	for _, r := range classRules {
		p := strings.Fields(r.Prefix)
		if len(p) <= len(path) && slices.Equal(p, path[:len(p)]) && len(p) > best {
			best, out = len(p), r
		}
	}
	return out, best >= 0
}

// allows reports whether the class has every bit of the row. A class with
// 'all' has them all.
func (c *Class) allows(bits []string) bool {
	if c == nil {
		return true
	}
	if slices.Contains(c.Permissions, "all") {
		return true
	}
	for _, b := range bits {
		if !slices.Contains(c.Permissions, b) {
			return false
		}
	}
	return true
}

// canSee reports whether the class sees the hierarchy of a Junos statement
// (its path); when not, it returns the row that hides it.
func (c *Class) canSee(path []string) (bool, ClassRule) {
	r, ok := classRuleFor(path)
	if !ok {
		return true, ClassRule{}
	}
	return c.allows(r.Bits), r
}

// --- pattern helpers ---------------------------------------------------------------

// matchPrefix matches a pattern against the start of a path. '$' captures
// the object's name. It returns the captured name and where it was.
func matchPrefix(pattern, path []string) (name string, at int, ok bool) {
	if len(path) < len(pattern) {
		return "", -1, false
	}
	at = -1
	for i, p := range pattern {
		if p == "$" {
			name, at = path[i], i
			continue
		}
		if p != path[i] {
			return "", -1, false
		}
	}
	return name, at, true
}
