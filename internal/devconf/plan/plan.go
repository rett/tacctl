package plan

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// Options are the inputs of Plan that are not the comparison.
type Options struct {
	// Sections limits the plan to the named sections (empty: every
	// plannable one). 'netconf' and 'breakglass' are never plannable and
	// naming them is ErrNeverEmitted.
	Sections []string
	// Secrets emits every secret statement of the planned sections by value
	// (D98); NoSecrets emits them with '<SECRET>' in place of the value.
	// Neither: a missing secret by value, a present or not-visible one not
	// at all.
	Secrets, NoSecrets bool
	// Writable, when not nil, names the sections the caller can commit; a
	// section it maps to false is skipped with the reason 'not writable'.
	Writable map[string]bool
	// Class is the caller's login class on a Junos device (nil: not known,
	// everything is planned). See ClassRule.
	Class *Class
	// From is the address the person is logged in from (--from), for the
	// management-filter check of D97; empty: not given.
	From string
	// Scope names the scope in the sensitivity line of the header.
	Scope string
	// Syntax is the Cisco device's configuration syntax, one of SyntaxIOS12
	// and SyntaxModern: the caller passes the device's one resolved
	// configuration syntax (D113: the setting, else the pull's version
	// line; never the ssh flag). It is ignored for Junos. For a Cisco plan
	// the empty string is refused (every section is skipped with
	// KindNotPlannable): a caller that forgets it must not get the
	// lock-out direction silently.
	Syntax string
	// Login are the vty and console login leaves of the pulled record, for
	// the IOS back-out (D106 (ii)). When empty they are read from the
	// extraction with LoginLeaves; when that does not know either, the aaa
	// section is refused with the pull command.
	Login []LoginLeaf
	// EnableSecret is the record's enable-secret presence note ("present",
	// "absent", or "" when not known), for the D106 (i) warning. When empty
	// the extraction's notes are read.
	EnableSecret string
	// Device is the device's name, used in the pull command of the refusal
	// texts ('tacctl device config pull <name>').
	Device string
	// PolicyGaps are the policy values the standard needs and the scope has
	// not set, each as the sentence the report carries as a warning
	// (devices.PolicyGaps, D119): the statement is left out of the rendering,
	// and nothing here is an irregularity of the device.
	PolicyGaps []string
	// Converge asks for the cleanup region (--converge, D111): the removals
	// of the extras the plan leaves, in a second region of their own
	// (Delta.Cleanup). The plan's own region is the same with or without it.
	Converge bool
	// BreakglassHeld, when not nil, says the server has been told not to
	// answer this device ('tacctl breakglass hold', D124): the report names
	// it before its items, since the check below cannot pass while it
	// stands, and the cover page marks the device. A pure input: the planner
	// never reads the record itself.
	BreakglassHeld *BreakglassHold
	// WTI are the facts of a WTI unit's plan that neither the rendering nor
	// the comparison say (ignored for any other vendor).
	WTI WTIFacts
}

// BreakglassHold is what a plan says of a hold: when it was made, as the
// caller shows times, and by whom.
type BreakglassHold struct {
	Since, By string
}

// The configuration syntaxes of a Cisco plan (Options.Syntax).
const (
	// SyntaxIOS12 is the IOS 12.x rendering.
	SyntaxIOS12 = "ios12"
	// SyntaxModern is the IOS 15 and IOS-XE rendering.
	SyntaxModern = "modern"
)

// syntaxUnknownWhy is the reason a Cisco plan with no Options.Syntax gives.
func syntaxUnknownWhy(device string) string {
	name := device
	if name == "" {
		name = "<name>"
	}
	return "the configuration syntax of this device is not known: run `tacctl device config pull " + name +
		"` or `tacctl device config-syntax " + name + " ios12|modern`"
}

// systemUnreadWhy is the reason a plan with a system block has no system
// section from a pull that predates the block.
func systemUnreadWhy(device string) string {
	name := device
	if name == "" {
		name = "<name>"
	}
	return "the system block of this scope is newer than the pull of this device, so its system settings were not read: run `tacctl device config pull " +
		name + "` to plan them"
}

// PlanOrder is the order the sections go in a block (D95 for Junos, §4b for
// IOS).
//
// The system section (Junos, 0.2.7) follows snmp and comes before mgmt-acl,
// which stays last; Plan leaves it out of a plan whose rendering has none.
func PlanOrder(family string) []string {
	if family == devconf.FamilyIOS {
		return []string{"aaa", "roles", "snmp", "mgmt-acl"}
	}
	if family == devconf.FamilyWTI {
		// the unit's checklist goes page 25 first (it cannot lock anybody
		// out), then the AAA pages, and the IP tables paste last
		return []string{devconf.SectionSNMP, devconf.SectionAAA, devconf.SectionMgmtACL}
	}
	return []string{"roles", "aaa", "snmp", devconf.SectionSystem, "mgmt-acl"}
}

// never are the two sections that are never planned.
var never = []string{"netconf", "breakglass"}

// secOut is what one section's planner returns.
type secOut struct {
	lines        []Line
	kept         []Kept
	skipped      []Skip
	inherited    []string
	why          []string
	warnings     []string
	unattributed []string
	withheld     []string
	// replaced counts statements the plan supersedes (set in place).
	presentSecrets, hiddenSecrets int
	// refused is set when the whole section is left out; refusedKind says
	// which kind of skip it is (default KindRefused).
	refused     string
	refusedKind string
	// partial describes a section planned in part (class limits).
	partial string
	// byHand are the steps to type by hand, outside any region, for a unit
	// that is refused (D117).
	byHand []string
}

// DECISION: Plan runs devconf.CompareAll itself from the extraction and the
// rendering (the signature of plan §5), so a caller cannot hand it a
// comparison that is not of these two inputs.
//
// DECISION: --secrets re-pushes every secret statement of every selected
// section that the caller's class sees, also when nothing else of the
// section differs (the way to rotate a key; presence is all the comparison
// can tell).
//
// Plan computes the delta of one device: expected is devices.Managed's
// result for it, current the extraction of the last pull (read with the
// expected sections, as devconf.Extract takes them), plain the extraction of
// the plain 'display set' view of the same pull (nil Sections: the record has
// none and the inheritance check is skipped, Delta.InheritanceChecked says
// so).
//
// The delta is computed from devconf.CompareAll's lines (the '-', '+' and
// '!' ones), not from any raw text. Only IOS planners read the extraction's
// ordered statements, for an access list's entry order.
func Plan(vendor string, expected []devices.Section, current, plain devconf.Extracted, opt Options) (Delta, error) {
	fam, err := devconf.Family(vendor)
	if err != nil {
		return Delta{}, fmt.Errorf("%w: %q", ErrUnsupported, vendor)
	}
	if fam == devconf.FamilyIOS && opt.Syntax != "" && opt.Syntax != SyntaxIOS12 && opt.Syntax != SyntaxModern {
		return Delta{}, fmt.Errorf("%w: unknown configuration syntax %q (ios12 or modern)", ErrUsage, opt.Syntax)
	}
	if opt.Secrets && opt.NoSecrets {
		return Delta{}, fmt.Errorf("%w: --secrets and --no-secrets exclude each other", ErrUsage)
	}
	for _, s := range opt.Sections {
		if slices.Contains(never, s) {
			return Delta{}, fmt.Errorf("%w: %s", ErrNeverEmitted, s)
		}
		if !slices.Contains(devconf.SectionNames, s) {
			return Delta{}, fmt.Errorf("%w: unknown section %q", ErrUsage, s)
		}
	}
	current.Vendor = fam
	if fam == devconf.FamilyWTI {
		// A unit has no statements to paste: its plan is a checklist of menu
		// steps and one IP tables block (wti.go).
		return planWTI(expected, current, opt)
	}
	results, err := devconf.CompareAll(expected, current)
	if err != nil {
		return Delta{}, err
	}
	byName := map[string]devconf.SectionResult{}
	for _, r := range results {
		byName[r.Name] = r
	}

	d := Delta{Vendor: fam, Scope: opt.Scope, InheritanceChecked: len(plain.Sections) > 0, BreakglassHeld: opt.BreakglassHeld}
	if fam == devconf.FamilyIOS {
		d.Syntax = opt.Syntax
	}
	// Only Junos has groups: an IOS plan has no inheritance to check.
	d.InheritanceChecked = d.InheritanceChecked && fam == devconf.FamilyJunos
	p := &planner{fam: fam, opt: opt, cur: current, plain: plain, checked: d.InheritanceChecked}
	p.exp = expected
	if fam == devconf.FamilyJunos {
		p.blk = blockObjectsOf(expected, opt.Scope)
	}
	if fam == devconf.FamilyIOS {
		p.prepareIOS(byName)
	}

	for _, name := range PlanOrder(fam) {
		// the system section exists only where the rendering has one
		if name == devconf.SectionSystem && len(p.expected(name).Lines) == 0 {
			continue
		}
		r := byName[name]
		sp := SectionPlan{Name: name}
		// a system section the record has not read has its own words, below
		unread := name == devconf.SectionSystem && r.State == devconf.StateNA
		for _, n := range r.Notes {
			if !slices.Contains(d.Notes, n) && !unread {
				d.Notes = append(d.Notes, n)
			}
		}
		switch {
		case len(opt.Sections) > 0 && !slices.Contains(opt.Sections, name):
			sp.State = StateNotSelected
		case fam == devconf.FamilyIOS && opt.Syntax == "":
			// M9: the dialect is a fact the caller must give; without it
			// nothing is typed (the modern default would lock out an IOS
			// 12.x device).
			sp.State, sp.Why, sp.Kind = StateSkipped, syntaxUnknownWhy(opt.Device), KindNotPlannable
			d.Skipped = append(d.Skipped, Skip{name, KindNotPlannable, sp.Why})
			d.Warnings = appendNew(d.Warnings, sp.Why)
		case opt.Writable != nil && !opt.Writable[name]:
			sp.State, sp.Why, sp.Kind = StateSkipped, "not writable by the caller", KindNotWritable
			d.Skipped = append(d.Skipped, Skip{name, KindNotWritable, sp.Why})
		case unread:
			// the block is newer than the pull: nothing of the section was
			// read, and nothing is guessed
			sp.State, sp.Why, sp.Kind = StateSkipped, systemUnreadWhy(opt.Device), KindNotPlannable
			d.Skipped = append(d.Skipped, Skip{name, KindNotPlannable, sp.Why})
			d.Warnings = appendNew(d.Warnings, sp.Why)
		case r.State == devconf.StateNA:
			sp.State = StateNA
		// DECISION: a section whose every compared statement is a secret the
		// login could not read is "not visible" and left alone, unless
		// --secrets asks for the values to be pushed.
		case r.State == devconf.StateNotVisible && !opt.Secrets:
			sp.State = StateNotVisible
			sp.Why = "everything it compares is a secret the pull's login could not read"
			d.Counts.SecretsNotVisible += r.NotVisible
		default:
			var o secOut
			if fam == devconf.FamilyIOS {
				o = p.iosSection(name, r)
			} else {
				o = p.junosSection(name, r)
			}
			d.merge(&sp, o)
		}
		d.Sections = append(d.Sections, sp)
	}
	for _, n := range never {
		d.Sections = append(d.Sections, SectionPlan{Name: n, State: StateNever})
	}
	// D118: the lines that use the lists (the console's and the vty lines'
	// login method) come after roles, snmp and mgmt-acl, and (HIGH 5) command
	// authorization goes last in the whole block.
	var early, leaves, late []Line
	for _, l := range d.Lines {
		switch {
		case lateAAA(l):
			l.Late = true
			late = append(late, l)
		case isLoginLeafLine(l):
			l.Leaf = true
			leaves = append(leaves, l)
		default:
			early = append(early, l)
		}
	}
	// The console first, then the vty ranges by their first line.
	slices.SortStableFunc(leaves, func(a, b Line) int { return leafOrder(a) - leafOrder(b) })
	d.Lines = slices.Concat(early, leaves, late)
	if len(late) > 0 {
		d.Warnings = append(d.Warnings, "the block switches command authorization on ('aaa authorization commands', 'config-commands') with its last lines: from then on every command is authorized by the server, so paste it as a user the server knows (or with local first), and keep the second terminal for the back-out")
	}
	// The comparison's note about a missing enable secret and the plan's own
	// warning say the same: the warning (which says what to do) stands.
	if slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.HasPrefix(w, "the device has no enable secret") }) {
		d.Notes = slices.DeleteFunc(d.Notes, func(n string) bool { return strings.HasPrefix(n, "no enable secret on the device") })
	}
	for _, g := range opt.PolicyGaps {
		d.Warnings = appendNew(d.Warnings, g)
	}
	p.finish(&d)

	// The report: the extras with their removal lines, the items in plain
	// words with the region lines that fix them (D110, D111).
	p.buildExtras(&d)
	p.buildItems(&d, byName)
	if fam == devconf.FamilyJunos && !d.Empty() {
		d.Backout = p.junosBackout(d)
	}
	if !d.Empty() {
		lineNo := map[int]int{}
		for n, rl := range RegionLines(d, Header{}, Wrapper{}) {
			if rl.Line >= 0 {
				lineNo[rl.Line] = n + 1
			}
		}
		for i := range d.Items {
			if !d.Items[i].Fixed {
				continue
			}
			var ns []int
			for _, li := range d.Items[i].Lines {
				if n, ok := lineNo[li]; ok {
					ns = append(ns, n)
				}
			}
			d.Items[i].Action = "Fixed by region " + lineNumbers(ns) + "."
		}
	}

	// --converge: the cleanup region (D111), from the extras above.
	if opt.Converge {
		p.buildCleanup(&d)
	}

	// Defensive: nothing on the never list may be in the block.
	for _, l := range slices.Concat(d.Lines, d.Cleanup.Lines) {
		if id, bad := neverMatch(fam, l); bad {
			return Delta{}, fmt.Errorf("plan: internal error: %q is on the never-emitted list (%s)", l.Shown(), id)
		}
	}
	return d, nil
}

// merge folds one section's output into the delta.
func (d *Delta) merge(sp *SectionPlan, o secOut) {
	sp.Why = strings.Join(o.why, "; ")
	d.Warnings = appendNew(d.Warnings, o.warnings...)
	d.Unattributed = appendNew(d.Unattributed, o.unattributed...)
	d.Withheld = appendNew(d.Withheld, o.withheld...)
	d.Inherited = appendNew(d.Inherited, o.inherited...)
	// the steps repeat lines on purpose ('exit' ends each submode): kept as given
	d.ByHand = append(d.ByHand, o.byHand...)
	d.Skipped = append(d.Skipped, o.skipped...)
	switch {
	case o.refused != "":
		kind := o.refusedKind
		if kind == "" {
			kind = KindRefused
		}
		sp.State, sp.Why, sp.Kind = StateSkipped, o.refused, kind
		d.Skipped = append(d.Skipped, Skip{sp.Name, kind, o.refused})
		d.Kept = append(d.Kept, o.kept...)
		return
	case len(o.lines) > 0:
		sp.State = StatePlanned
	default:
		sp.State = StateNoChange
		sp.Why = ""
	}
	sp.Statements = len(o.lines)
	if d.Vendor == devconf.FamilyIOS {
		sp.Statements = pastedLines(o.lines)
	}
	for i := range o.lines {
		o.lines[i].Section = sp.Name
	}
	d.Lines = append(d.Lines, o.lines...)
	d.Kept = append(d.Kept, o.kept...)
	d.Counts.SecretsPresent += o.presentSecrets
	d.Counts.SecretsNotVisible += o.hiddenSecrets
	if o.partial != "" {
		sp.Why = strings.TrimPrefix(sp.Why+"; "+o.partial, "; ")
	}
}

func appendNew(dst []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}

// planner holds what one Plan call shares between its section planners.
type planner struct {
	fam     string
	opt     Options
	exp     []devices.Section
	cur     devconf.Extracted
	plain   devconf.Extracted
	checked bool
	// noLocal is set when the IOS guards found no local user at privilege
	// 15 (the report gets an ACCESS item of its own).
	noLocal bool
	// ios holds the IOS-only state.
	ios *iosState
	// blk are the objects of the rendering that a configuration block put
	// there (nil: none), for the report's words.
	blk *blockObjects
}

func (p *planner) expected(name string) devices.Section {
	for _, s := range p.exp {
		if s.Name == name {
			return s
		}
	}
	return devices.Section{Name: name}
}

// inPlain reports whether a statement (compared form) of a section is in the
// plain view too, that is not inherited from a group.
func (p *planner) inPlain(section, stem string) bool {
	if !p.checked {
		return true
	}
	return slices.Contains(p.plain.Sections[section].Lines, stem)
}

// finish computes the counts and the header facts that need every section.
func (p *planner) finish(d *Delta) {
	for _, l := range d.Lines {
		switch l.Op {
		case OpSet:
			d.Counts.Set++
		case OpDelete:
			d.Counts.Delete++
		case OpInsert:
			d.Counts.Insert++
		case OpLine:
			d.Counts.Line++
		case OpNo:
			d.Counts.No++
		}
		if l.Secret {
			if l.HasValue {
				d.Counts.SecretsByValue++
			} else if strings.Contains(l.Text, "<SECRET>") {
				// a secret statement deleted by name holds no value and is
				// no placeholder
				d.Counts.Placeholders++
			}
		}
	}
	d.Counts.Kept = len(d.Kept)
	if p.opt.Class != nil {
		d.Class = p.opt.Class.Name
	}
	for _, l := range d.Lines {
		if l.Section == "aaa" && l.Op == OpLine && l.Text == "aaa new-model" && len(l.Context) == 0 {
			d.AddsAAA = true
		}
	}
	if d.AddsAAA && p.ios != nil {
		d.Login = p.ios.login
	}
	kinds := []string{}
	for _, l := range d.Lines {
		if l.Secret && l.HasValue {
			if k := secretKind(d.Vendor, l); k != "" && !slices.Contains(kinds, k) {
				kinds = append(kinds, k)
			}
		}
	}
	d.SecretKinds = kinds
}

// secretKind names what a secret line holds, for the sensitivity line.
func secretKind(family string, l Line) string {
	t := l.Elided
	if t == "" {
		t = l.Text
	}
	switch {
	case strings.Contains(t, "tacplus-server"), strings.HasPrefix(t, "tacacs-server host"), containsCtx(l, "tacacs server"):
		if family == devconf.FamilyIOS {
			return "TACACS+ KEY"
		}
		return "TACACS+ SECRET"
	case strings.Contains(t, "radius-server"), containsCtx(l, "radius server"):
		if family == devconf.FamilyIOS {
			return "RADIUS KEY"
		}
		return "RADIUS SECRET"
	case strings.Contains(t, "snmp community"), strings.Contains(t, "snmp-server community"), strings.Contains(t, "snmp trap-group"), strings.Contains(t, "snmp-server host"):
		return "SNMP COMMUNITY"
	case strings.Contains(t, "snmp v3"), strings.Contains(t, "snmp-server user"):
		return "SNMPv3 USER PASSWORDS"
	case strings.Contains(t, "ntp authentication-key"):
		return "NTP KEY"
	}
	return "SECRET"
}

func containsCtx(l Line, prefix string) bool {
	for _, c := range l.Context {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// --- shared statement helpers --------------------------------------------------------

// the notes Compare appends to a secret statement's stem.
const (
	noteSuffixPresent    = " (present, not compared)"
	noteSuffixAbsent     = " (not present)"
	noteSuffixNotVisible = " (not visible to this login)"
)

// stemOf returns a comparison line's statement without its note.
func stemOf(l devconf.DiffLine) string {
	t := l.Text
	if !l.Secret {
		return t
	}
	for _, s := range []string{noteSuffixPresent, noteSuffixAbsent, noteSuffixNotVisible} {
		if r, ok := strings.CutSuffix(t, s); ok {
			return r
		}
	}
	return t
}

// secretMark is the elided value in a stem.
const secretMark = "<secret>"

// isMark reports a word that stands for a secret in a stem: the mark, or a
// community's label ('<secret:1>', '<other:2>').
func isMark(w string) bool { return w == secretMark || devconf.IsLabel(w) }

// reMarks finds the marks of a stem's text.
var reMarks = regexp.MustCompile(`<secret>|<(?:secret|other):[1-9][0-9]*>`)

// shownSecret is a secret statement's stem with the value's place marked.
func shownSecret(stem string) string {
	if reMarks.MatchString(stem) {
		return stem
	}
	return stem + " " + secretMark
}

// placeholderOf is shownSecret with the --no-secrets placeholder.
func placeholderOf(stem string) string {
	return reMarks.ReplaceAllString(shownSecret(stem), "<SECRET>")
}

// splitTokens splits a statement into words; double and single quotes group
// and are dropped. A word is as the device prints it: inside double quotes a
// backslash and the character after it stay together (so '\"' does not end
// the quote and a login message's '\n' stays a '\n'), and quoteTok writes
// the word back the same way.
func splitTokens(s string) []string {
	var out []string
	var b strings.Builder
	in := rune(0)
	has := false
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case in == '"' && r == '\\':
			b.WriteRune(r)
			esc = true
		case in != 0:
			if r == in {
				in = 0
			} else {
				b.WriteRune(r)
			}
		case r == '"' || r == '\'':
			in, has = r, true
		case r == ' ' || r == '\t':
			if has || b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
				has = false
			}
		default:
			b.WriteRune(r)
		}
	}
	if has || b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// quoteTok writes a path token back the way a Junos statement has it: bare
// unless it holds a blank, a quote or a character Junos reads as structure.
// A token is in the form splitTokens gives (escapes as printed), so an escape
// in it stays, and a quote that is not escaped is.
func quoteTok(t string) string {
	if t == "" || strings.ContainsAny(t, " \t\"'\\;[]{}") {
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(t); i++ {
			switch c := t[i]; {
			case c == '\\' && i+1 < len(t):
				b.WriteByte(c)
				i++
				b.WriteByte(t[i])
			case c == '\\':
				b.WriteString(`\\`)
			case c == '"':
				b.WriteString(`\"`)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	return t
}

func joinTokens(ts []string) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = quoteTok(t)
	}
	return strings.Join(parts, " ")
}
