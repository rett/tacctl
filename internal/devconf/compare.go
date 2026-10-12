package devconf

// Extract, Normalise and Compare (D62, D64).

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// Extracted is what a device's configuration text holds of the managed
// sections.
type Extracted struct {
	// Vendor is the family the text was read as (junos or ios).
	Vendor string
	// Sections has the managed sections by name (the system section only
	// when the rendering has one, and on Junos); one with no statement on
	// the device has no Lines. Lines are in the compared form (see
	// Normalise): a secret's value is not in them, whatever the device
	// printed (encrypted, hashed or masked), and Secret marks the lines
	// that carried one.
	Sections map[string]devices.Section
	// SecretsVisible is whether the login that read the text could see the
	// device's secrets. Junos shows a class without the secret permission
	// its secrets masked ('/* SECRET-DATA */') and omits a server's secret
	// altogether, so it is false when a statement of the text holds the
	// masking comment, and true otherwise (always true for IOS). The caller
	// knows better when it knows the login's class: ExtractWith takes the
	// value and the field may be set after.
	SecretsVisible bool
}

// Options are the optional inputs of ExtractWith.
type Options struct {
	// Expected is devices.Managed's result for the device: it says which
	// named objects are tacctl's and claims the statements it renders.
	Expected []devices.Section
	// SecretsVisible overrides what the text suggests (nil: derive it).
	SecretsVisible *bool
}

// Extract returns the managed sections of a device's configuration
// text: Junos 'show configuration | display inheritance no-comments |
// display set' or IOS/IOS-XE 'show running-config'. A section is the
// statements under its hierarchy (plan D62): the system's AAA keys, the
// login classes and users, the management filter, 'snmp', 'system services
// netconf' on Junos, and the login message, domain, time zone, name servers
// and NTP where the rendering has a system section (a login message is kept
// as a mark of its size and a digest, never as text); 'aaa', the server
// blocks, 'username', 'privilege', the management ACL and the VTY
// 'access-class', 'snmp-server' and 'netconf-yang' on IOS.
//
// The optional expected sections (devices.Managed's result for the device)
// say which named objects are tacctl's, so a login class, a filter or an
// ACL of the operator's own is not reported as a stray, and claim the
// statements they render wherever they sit. Without them the classes and
// users are all kept, and the filters and ACLs the device applies on lo0,
// the VTY lines and SNMP, and tacctl's default names.
//
// What Extract returns holds no secret value (a departure from plan 6,
// which had the encrypted keys in the sections file and the diff): a secret
// is compared by presence, and a value kept is a value that can be read
// back from the store or a --json document.
//
// ErrParse (wrapped) is returned when the text is not a configuration of
// the vendor, ErrUnsupportedVendor for a vendor with no extractor.
func Extract(vendor, raw string, expected ...devices.Section) (Extracted, error) {
	return ExtractWith(vendor, raw, Options{Expected: expected})
}

// ExtractWith is Extract with its options.
func ExtractWith(vendor, raw string, opt Options) (Extracted, error) {
	fam, err := Family(vendor)
	if err != nil {
		return Extracted{}, err
	}
	if fam == FamilyJunos {
		return junosExtract(raw, opt.Expected, opt.SecretsVisible)
	}
	return ciscoExtract(raw, opt.Expected, opt.SecretsVisible)
}

// Normalise puts a section, rendered or extracted, in the form Compare
// compares: one canonical statement per line, bracket lists and blocks
// expanded, Cisco submodes joined to their context, a secret's value
// elided (the line holds its stem) and Secret set, a repeated statement
// dropped (a secret statement is kept as it comes: they are compared as a
// multiset). Its output holds no secret value and is safe to print.
func Normalise(vendor string, s devices.Section) (devices.Section, error) {
	fam, err := Family(vendor)
	if err != nil {
		return devices.Section{}, err
	}
	return toSection(s.Name, uniq(canonFor(fam)(s.Lines, s.Secret, newLabels(fam, s.Lines)))), nil
}

// Elide returns the statements of lines as Normalise shows them: the
// secret's value left out. A line can expand to several statements.
func Elide(vendor string, lines []string, secret []bool) ([]string, error) {
	return ElideIn(vendor, lines, secret, lines)
}

// ElideIn is Elide for lines of a rendering: a community's name is labelled
// as in the whole rendered section (devices.Managed's lines), so one line
// elided alone has the label the comparison gives it.
func ElideIn(vendor string, lines []string, secret []bool, rendered []string) ([]string, error) {
	fam, err := Family(vendor)
	if err != nil {
		return nil, err
	}
	return toSection("", uniq(canonFor(fam)(lines, secret, newLabels(fam, rendered)))).Lines, nil
}

// Fingerprint is the SHA-256 of a section's statements in the compared form
// (order does not matter), hex: it changes with the section's statements,
// not with a secret's value, and it reveals none.
func Fingerprint(vendor string, s devices.Section) (string, error) {
	n, err := Normalise(vendor, s)
	if err != nil {
		return "", err
	}
	texts := slices.Clone(n.Lines)
	slices.Sort(texts)
	sum := sha256.Sum256([]byte(strings.Join(texts, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

// State is the outcome of comparing one section (D64).
type State string

const (
	// StateOK: every expected statement is on the device and nothing else is
	// in the section's hierarchy but the device's own statements the planner
	// keeps by rule (SectionResult.Unmanaged counts them).
	StateOK State = "ok"
	// StateDiffers: a statement is missing, extra or out of order.
	StateDiffers State = "differs"
	// StateMissing: nothing of the section is on the device.
	StateMissing State = "missing"
	// StateNA: tacctl renders nothing for the section.
	StateNA State = "n/a"
	// StateNotVisible: everything expected is a secret the login could not
	// read, so nothing can be said.
	StateNotVisible State = "not visible"
)

// The Op of a DiffLine.
const (
	// OpMissing: expected, not on the device.
	OpMissing byte = '-'
	// OpExtra: on the device, not expected.
	OpExtra byte = '+'
	// OpSame: on both sides (a secret by presence).
	OpSame byte = '='
	// OpNotVisible: an expected secret the device omits from this login's
	// text (a Junos server's secret); not a difference.
	OpNotVisible byte = '?'
	// OpOrder: statements both sides have, in another order (a Junos
	// authentication order or the terms of a filter; the entries of an
	// ACL).
	OpOrder byte = '!'
	// OpInfo: a statement on the device in a section tacctl renders
	// nothing for; informational, not a difference.
	OpInfo byte = '~'
)

// DiffLine is one statement of a comparison. Text never holds a secret's
// value.
type DiffLine struct {
	Op     byte
	Text   string
	Secret bool
	// Unmanaged marks an extra ('+') statement that is the device's own,
	// kept by rule: not a difference.
	Unmanaged bool
}

// SectionResult is the comparison of one section.
type SectionResult struct {
	Name  string
	State State
	// Lines are the statements: expected ones in the rendered order ('='
	// or '-' or '?'), then the device's extra ones ('+'), then the order
	// findings ('!'); for a section tacctl renders nothing for, the
	// device's statements as '~'.
	Lines []DiffLine
	// NotVisible counts the '?' lines: statements that could not be
	// checked because the login cannot read secrets.
	NotVisible int
	// Notes are findings that are not drift: the management filter exists
	// but is not applied on lo0 (the operator's step), IOS lines that
	// 'show running-config' does not print.
	Notes []string
	// Unmanaged counts the '+' lines that are the device's own statements,
	// kept by rule (another community, a trap group, the SNMP name): with
	// nothing else different the section is ok all the same.
	Unmanaged int
}

// StateText is the state as the text output shows it: 'ok (+N unmanaged)'
// for a section that is ok beside statements of the device's own.
func (r SectionResult) StateText() string {
	if r.State == StateOK && r.Unmanaged > 0 {
		return "ok (+" + strconv.Itoa(r.Unmanaged) + " unmanaged)"
	}
	return string(r.State)
}

// UnmanagedNote is the note of a section with statements of the device's
// own.
func (r SectionResult) UnmanagedNote() string {
	if r.Unmanaged == 1 {
		return "1 statement of the device's own, kept on purpose"
	}
	return strconv.Itoa(r.Unmanaged) + " statements of the device's own, kept on purpose"
}

// noteLegacyCommunities is the note of a record whose community names are
// not labelled.
const noteLegacyCommunities = "the SNMP communities of this record (made by an older tacctl) are not told apart: " +
	"compared by presence, and a statement under a community is left alone, until the next pull"

// Notes after a secret statement's stem; the value is never printed.
const (
	notePresent    = " (present, not compared)"
	noteAbsent     = " (not present)"
	noteNotVisible = " (not visible to this login)"
)

// isLo0Apply reports a Junos statement that applies a filter on lo0.
func isLo0Apply(x stmt) bool {
	_, ok := lo0Apply(x.path)
	return ok
}

// omitted reports a Junos statement that a login without the secret
// permission is not shown at all ('system tacplus-server <addr> secret'):
// everything else a secret is masked, so it still appears. [S] the lab
// switch's engineer view.
func omitted(x stmt) bool {
	p := x.path
	return len(p) >= 4 && p[0] == "system" && (p[1] == "tacplus-server" || p[1] == "radius-server") && p[3] == "secret"
}

// orderGroup returns the ordered list a statement is an element of: the
// group and the element. Position matters for a Junos authentication order
// and for the terms of a firewall filter, and for the entries of an ACL.
func orderGroup(fam string, x stmt) (group, element string, ok bool) {
	p := x.path
	if fam == FamilyJunos {
		switch {
		case len(p) >= 3 && p[0] == "system" && p[1] == "authentication-order":
			return "system authentication-order", p[2], true
		case len(p) >= 7 && p[0] == "firewall" && p[1] == "family" && p[3] == "filter" && p[5] == "term":
			return strings.Join(p[:5], " "), p[6], true
		}
		return "", "", false
	}
	switch {
	case len(p) == 2 && (strings.HasPrefix(p[0], "ip access-list ") || strings.HasPrefix(p[0], "ipv6 access-list ")):
		return p[0], p[1], true
	case len(p) == 1 && strings.HasPrefix(p[0], "access-list "):
		if f := strings.Fields(p[0]); len(f) >= 4 && f[2] != "remark" {
			return strings.Join(f[:2], " "), strings.Join(f[2:], " "), true
		}
	}
	return "", "", false
}

// sequences are the elements of each ordered group, in order of first
// appearance.
func sequences(fam string, in []stmt) map[string][]string {
	out := map[string][]string{}
	for _, x := range in {
		if g, e, ok := orderGroup(fam, x); ok && !slices.Contains(out[g], e) {
			out[g] = append(out[g], e)
		}
	}
	return out
}

// runs reduces an ACL's entries to sequences of sets: consecutive entries
// with one action are one set.
func runs(entries []string) [][]string {
	var out [][]string
	var last string
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

// orderFindings compares the order of the elements both sides have, per
// group.
func orderFindings(fam string, exp, dev []stmt) []DiffLine {
	es, ds := sequences(fam, exp), sequences(fam, dev)
	groups := make([]string, 0, len(es))
	for g := range es {
		groups = append(groups, g)
	}
	slices.Sort(groups)
	var out []DiffLine
	for _, g := range groups {
		d, ok := ds[g]
		if !ok {
			continue
		}
		var ce, cd []string
		for _, e := range es[g] {
			if slices.Contains(d, e) {
				ce = append(ce, e)
			}
		}
		for _, e := range d {
			if slices.Contains(es[g], e) {
				cd = append(cd, e)
			}
		}
		same := slices.Equal(ce, cd)
		if fam == FamilyIOS {
			re, rd := runs(ce), runs(cd)
			same = len(re) == len(rd)
			for i := 0; same && i < len(re); i++ {
				same = slices.Equal(re[i], rd[i])
			}
		}
		if !same {
			out = append(out, DiffLine{Op: OpOrder, Text: g + ": order differs, expected " +
				strings.Join(ce, ", ") + "; device " + strings.Join(cd, ", ")})
		}
	}
	return out
}

// Compare compares what tacctl renders for one section with what the device
// has, line by line (D64). Both sides are normalised, so either may be the
// raw text of Section.Lines. Secrets are compared by presence: a statement
// the device prints with its value hashed, encrypted or masked equals the
// rendered one that has the clear value, whatever the value, and equal
// elided forms are counted (a second community with the managed one's
// options is an extra).
//
// secretsVisible says whether the login that read the device could see its
// secrets (Extracted.SecretsVisible). When it could not, an expected
// statement of the kind the device omits for that login (a Junos server's
// secret) that the device did not print is '?', never '-', and never makes
// the section differ; everything else the device masks still appears, so
// its absence is a difference.
//
// An expected section with no statement is n/a, the device's statements of
// the hierarchy listed as '~'; a device section with none is missing.
// Order is compared for a Junos authentication order and filter terms and
// for ACL entries (runs of one action as sets): '!'.
func Compare(vendor string, expected, got devices.Section, secretsVisible bool) (SectionResult, error) {
	fam, err := Family(vendor)
	if err != nil {
		return SectionResult{}, err
	}
	canon := canonFor(fam)
	lb := newLabels(fam, expected.Lines)
	dev := uniq(canon(got.Lines, got.Secret, lb))
	res := SectionResult{Name: expected.Name}
	if res.Name == "" {
		res.Name = got.Name
	}
	if slices.ContainsFunc(dev, func(x stmt) bool { return legacyCommunity(fam, x) }) {
		// A record of an older tacctl: its community names are all one mark,
		// so the rendering's are compared that way too (by presence).
		lb = nil
		res.Notes = append(res.Notes, noteLegacyCommunities)
	}
	exp := uniq(canon(expected.Lines, expected.Secret, lb))
	if res.Name == SectionBreakGlass {
		var notes []string
		dev, notes = foldLoginNames(exp, dev)
		res.Notes = append(res.Notes, notes...)
	}
	expStems := map[string]bool{}
	for _, x := range exp {
		expStems[x.stem] = true
	}

	// Statements that are findings of their own, not differences: the lo0
	// application (the operator's step: a note when the filter exists and
	// is not applied) and, on IOS, the lines running-config does not print.
	var lo0 []stmt
	if fam == FamilyJunos {
		var keep []stmt
		for _, x := range dev {
			if isLo0Apply(x) && !expStems[x.stem] {
				lo0 = append(lo0, x)
				continue
			}
			keep = append(keep, x)
		}
		dev = keep
	}
	// What the device says about 'enable' is a finding, not a statement the
	// rendering can have: by presence, a note when none is set and the
	// rendering turns AAA on (a local user of level 15 is then the only
	// way up), and a section that holds nothing else is still missing.
	var enable string
	if fam == FamilyIOS {
		var notes []string
		dev, notes = withoutImplicitIOS(exp, dev)
		res.Notes = append(res.Notes, notes...)
		// The source interface is the operator's where the scope sets none
		// (D119): a device's value is no extra then, whatever record it comes
		// from.
		if !slices.ContainsFunc(exp, isSourceInterface) {
			dev = slices.DeleteFunc(dev, isSourceInterface)
		}
		// IOS prints 'aaa session-id common' by itself; tacctl renders it, and
		// where a rendering has none (an operator's own expectation) it is
		// no extra.
		if !slices.ContainsFunc(exp, func(x stmt) bool { return x.stem == sessionIDCommon }) {
			dev = slices.DeleteFunc(dev, func(x stmt) bool { return x.stem == sessionIDCommon })
		}
		// The standard has no enable list: one that asks a server lets any
		// user the server knows reach privilege 15 with their own password.
		// A device's list is therefore extra, but for the one that says what
		// IOS does with no list at all ('enable' alone, the local secret).
		if !slices.ContainsFunc(exp, isEnableList) {
			dev = slices.DeleteFunc(dev, func(x stmt) bool {
				return isEnableList(x) && x.path[0] == enableLocalOnly
			})
		}
		var keep []stmt
		for _, x := range dev {
			if x.stem == enableHeld || x.stem == enableNone {
				enable = x.stem
				continue
			}
			keep = append(keep, x)
		}
		dev = keep
		// The login leaves are read from the lines the device printed, by
		// range: a rendered 'line vty 0 15' is there when the device's
		// ranges with that leaf cover it. A section with neither a leaf
		// nor the marker is a record of an older tacctl, which did not read
		// them: not compared, and said so.
		known := enable != "" || slices.ContainsFunc(dev, func(x stmt) bool { return isLoginLeaf(x.path) })
		if known || len(dev) == 0 {
			dev = alignLogin(exp, dev)
		} else {
			var keepExp []stmt
			skipped := false
			for _, x := range exp {
				if isLoginLeaf(x.path) {
					skipped = true
					continue
				}
				keepExp = append(keepExp, x)
			}
			if skipped {
				exp = keepExp
				res.Notes = append(res.Notes, "the login method of the console and VTY lines is not in this record "+
					"(made by an older tacctl): not compared until the next pull")
			}
		}
	}
	if enable == enableNone && slices.ContainsFunc(exp, func(x stmt) bool { return x.stem == "aaa new-model" }) {
		res.Notes = append(res.Notes, "no enable secret on the device: with AAA on and the server unreachable, "+
			"a local user with privilege 15 is the only way to level 15")
	}
	onDev := map[string]int{}
	for _, x := range dev {
		onDev[x.stem]++
	}
	if fam == FamilyIOS {
		var keep []stmt
		noted := false
		for _, x := range exp {
			// [A] 'show running-config' does not print an SNMPv3 user.
			if onDev[x.stem] == 0 && len(x.path) == 1 && strings.HasPrefix(x.path[0], "snmp-server user ") {
				if !noted {
					res.Notes = append(res.Notes, "snmp-server user lines are not shown by running-config: not compared")
					noted = true
				}
				continue
			}
			keep = append(keep, x)
		}
		exp = keep
	}

	if len(exp) == 0 {
		res.State = StateNA
		for _, x := range dev {
			l := DiffLine{Op: OpInfo, Text: x.stem, Secret: x.secret}
			if x.secret {
				l.Text += notePresent
			}
			res.Lines = append(res.Lines, l)
		}
		return res, nil
	}

	// The match: each expected statement takes one equal device statement;
	// what the device has beyond is extra.
	budget := map[string]int{}
	allUnseen := true
	for _, x := range exp {
		var l DiffLine
		switch {
		case onDev[x.stem]-budget[x.stem] > 0:
			budget[x.stem]++
			l = DiffLine{Op: OpSame, Text: x.stem, Secret: x.secret}
			if x.secret {
				l.Text += notePresent
			}
			allUnseen = false
		case x.secret && !secretsVisible && fam == FamilyJunos && omitted(x):
			l = DiffLine{Op: OpNotVisible, Text: x.stem + noteNotVisible, Secret: true}
			res.NotVisible++
		default:
			l = DiffLine{Op: OpMissing, Text: x.stem, Secret: x.secret}
			if x.secret {
				l.Text += noteAbsent
			}
			allUnseen = false
		}
		res.Lines = append(res.Lines, l)
	}
	extra := 0
	rs := newRenderedSet(fam, expected, exp, lb)
	left := map[string]int{}
	for s, n := range budget {
		left[s] = n
	}
	for _, x := range dev {
		if left[x.stem] > 0 {
			left[x.stem]--
			continue
		}
		l := DiffLine{Op: OpExtra, Text: x.stem, Secret: x.secret, Unmanaged: unmanaged(fam, res.Name, x, rs)}
		if x.secret {
			l.Text += notePresent
		}
		res.Lines = append(res.Lines, l)
		if l.Unmanaged {
			res.Unmanaged++
			continue
		}
		extra++
	}
	order := orderFindings(fam, exp, dev)
	res.Lines = append(res.Lines, order...)
	missing := 0
	for _, l := range res.Lines {
		if l.Op == OpMissing {
			missing++
		}
	}

	if fam == FamilyJunos && res.Name == SectionMgmtACL {
		res.Notes = append(res.Notes, unappliedFilters(exp, dev, lo0)...)
	}

	// present counts the statements that are the section's own: a router
	// that has only the login method of its lines ('login local') has no
	// AAA of tacctl's on it, the lines being listed all the same.
	present := len(dev)
	if fam == FamilyIOS {
		for _, x := range dev {
			if isLoginLeaf(x.path) || x.stem == sessionIDCommon {
				present--
			}
		}
	}

	switch {
	case present == 0 && allUnseen:
		res.State = StateNotVisible
	case present == 0:
		res.State = StateMissing
	case missing > 0 || extra > 0 || len(order) > 0:
		res.State = StateDiffers
	default:
		res.State = StateOK
	}
	return res, nil
}

// unappliedFilters names the filters tacctl renders that are on the device
// but applied on no lo0 unit.
func unappliedFilters(exp, dev, lo0 []stmt) []string {
	filterOf := func(x stmt) string {
		if p := x.path; len(p) >= 5 && p[0] == "firewall" && p[1] == "family" && p[3] == "filter" {
			return p[4]
		}
		return ""
	}
	applied := map[string]bool{}
	for _, x := range lo0 {
		names, _ := lo0Apply(x.path)
		for _, n := range names {
			applied[n] = true
		}
	}
	for _, x := range dev {
		if names, ok := lo0Apply(x.path); ok {
			for _, n := range names {
				applied[n] = true
			}
		}
	}
	onDevice := map[string]bool{}
	for _, x := range dev {
		if n := filterOf(x); n != "" {
			onDevice[n] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, x := range exp {
		if n := filterOf(x); n != "" && !seen[n] {
			seen[n] = true
			if onDevice[n] && !applied[n] {
				out = append(out, "filter "+n+" is not applied on lo0")
			}
		}
	}
	return out
}

// CompareAll compares every managed section of a device: expected is
// devices.Managed's result (a section it leaves out is n/a), got is the
// extraction. The results are in SectionNames order.
func CompareAll(expected []devices.Section, got Extracted) ([]SectionResult, error) {
	out := make([]SectionResult, 0, len(SectionNames))
	for _, n := range SectionNames {
		e := sectionOf(expected, n)
		if optionalSection(n) {
			if !renders(expected, n) {
				// the scope has no such block: no section at all
				continue
			}
			if _, ok := got.Sections[n]; !ok {
				// A record made before the block was set (or by an older
				// tacctl) did not read the section: nothing is compared
				// until the next pull.
				out = append(out, SectionResult{Name: n, State: StateNA, Notes: []string{noteNoSystem}})
				continue
			}
		}
		g := got.Sections[n]
		g.Name = n
		r, err := Compare(got.Vendor, e, g, got.SecretsVisible)
		if err != nil {
			return nil, err
		}
		r.Name = n
		out = append(out, r)
	}
	return out, nil
}

// noteNoSystem is the note of a record that has no system section although
// the rendering has one.
const noteNoSystem = "the system block of this scope is newer than the pull of this record: " +
	"the system settings are not compared until the next pull"
