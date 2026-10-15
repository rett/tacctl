package plan

// The allow-list tripwire of an apply (0.2.9 plan D133). CheckRegion
// refuses anything but set, delete and insert statements, but it accepts a
// set of any hierarchy; before an apply types a line, Allowed asks the
// planner's own tables whether the line lies where the plan may write. The
// list is derived: a statement is allowed when its path lies under an owned
// row (owned.go) of a planned section, or is one the rendering of such a
// section emits; a row added to the tables is allowed by construction, and a
// hand-kept list that could drift is what this replaces. A never list
// refuses what no table may admit.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// ErrNotAllowed is the error of every refusal of Allowed (errors.Is).
var ErrNotAllowed = errors.New("plan: statement outside the allow-list")

// AllowError is one refusal. Statement is the line with a secret's value
// masked and cut: an error never holds a value.
type AllowError struct {
	Statement string
	// Never is set when a never-list row refused the line (whatever the
	// tables say).
	Never bool
	// Why is the reason.
	Why string
}

func (e *AllowError) Error() string {
	return "not allowed: " + e.Why + ": " + e.Statement
}

// Unwrap is ErrNotAllowed.
func (e *AllowError) Unwrap() error { return ErrNotAllowed }

// NeverRow is a hierarchy an apply never writes, whatever the tables name.
type NeverRow struct {
	ID string
	// Pattern is the path prefix, space separated; '?' is any one word.
	Pattern string
	// Anywhere, when not empty, must also be a word of the path after the
	// pattern.
	Anywhere string
	Why      string
}

// allowNever is the never list (D133) as data: the rows of owned.go's
// neverEmitted (applied by neverMatch) and these. The invoking login's own
// user is refused by Allow.Login.
var allowNever = []NeverRow{
	{ID: "junos.root-authentication", Pattern: "system root-authentication", Why: "the root account's credentials"},
	{ID: "junos.services", Pattern: "system services", Why: "how the device is reached (ssh, netconf, web)"},
	{ID: "junos.interfaces", Pattern: "interfaces", Why: "the device's interfaces"},
	{ID: "junos.groups", Pattern: "groups", Why: "configuration groups"},
	{ID: "junos.apply-groups", Pattern: "apply-groups", Why: "configuration groups"},
	{ID: "junos.user-authentication", Pattern: "system login user ?", Anywhere: "authentication", Why: "a local user's credentials"},
	{ID: "junos.user-root", Pattern: "system login user root", Why: "the root user"},
	{ID: "junos.user-uid", Pattern: "system login user ?", Anywhere: "uid", Why: "a local user's uid (the device assigns it)"},
}

// AllowNever returns the never list.
func AllowNever() []NeverRow { return slices.Clone(allowNever) }

// Allow is what a statement is held against: the vendor's tables, the
// sections the plan has, and what the rendering says.
type Allow struct {
	// Vendor is the registry's word or the family; only Junos has an
	// allow-list (a statement of another vendor is refused).
	Vendor string
	// Sections are the planned sections. Nil: every section of PlanOrder.
	Sections []string
	// Expected is the rendering (devices.Managed's result). With it a '$'
	// of a row must be an object the rendering names (a class, a template
	// user, tacctl's server), and a statement the rendering emits is allowed
	// beside the tables'. Nil: the tables alone, every name is accepted.
	Expected []devices.Section
	// Login is the invoking login: its user is never written.
	Login string
	// LoginClass is the invoking login's login class: nothing under
	// 'system login class <LoginClass>' is written, but the statements of
	// Expected the plan's own lock-out guards have already held. Empty:
	// unknown, which an apply must not leave when it knows it.
	LoginClass string
}

// Allowed holds a line against the tables of every section, with no rendering
// and no login: the part of the allow-list that needs no input.
//
// IT IS NOT THE APPLY'S CHECK. With no rendering a '$' of a row is any name
// (a class, a user, a server that is not tacctl's), so the statement of
// another object passes. A apply, and every caller that types on a device,
// uses Allow with Expected (and Login, LoginClass) set, and Ready to be sure
// it is.
func Allowed(vendor, line string) error { return Allow{Vendor: vendor}.Check(line) }

// ErrNoExpected is the error of Ready: the allow-list has no rendering to
// hold the names against.
var ErrNoExpected = errors.New("plan: no expected statements")

// Ready reports whether the allow-list is fit to guard an apply: it must
// hold the rendering (Expected) whenever it plans any section, or the tables
// alone would admit every name (fail closed). A nil result says only that the
// input is there; Check and CheckDelta say whether a statement passes.
func (a Allow) Ready() error {
	if len(a.Expected) > 0 {
		return nil
	}
	if a.Sections != nil && len(a.Sections) == 0 {
		return nil
	}
	return fmt.Errorf("%w: the allow-list would accept any name of a class, user or server", ErrNoExpected)
}

// refuse builds an AllowError with the statement masked.
func refuse(line string, never bool, format string, a ...any) error {
	toks := splitTokens(line)
	var verb []string
	if len(toks) > 0 && slices.Contains(junosVerbs, toks[0]) {
		verb, toks = toks[:1], toks[1:]
	}
	toks = append(verb, maskSecretTokens(toks)...)
	// four words name the hierarchy; the rest may hold a value no rule knows
	if len(toks) > 4 {
		toks = append(toks[:4:4], "...")
	}
	return &AllowError{Statement: joinTokens(toks), Never: never, Why: fmt.Sprintf(format, a...)}
}

// Check reports why a statement may not be typed (nil: it may).
func (a Allow) Check(line string) error {
	fam, err := devconf.Family(a.Vendor)
	if err != nil || fam != devconf.FamilyJunos {
		return refuse("", false, "there is no allow-list for vendor %q", a.Vendor)
	}
	// the syntax of a statement (no pipe, brace, semicolon or control
	// character; a set, delete or insert); a comment is not a statement
	if strings.HasPrefix(line, "#") {
		return refuse(line, false, "a comment is not a statement")
	}
	if err := junosStatementOK(line); err != nil {
		return refuse(line, false, "%v", err)
	}
	// Junos knows double quotes only: a single quote is no quoting there,
	// whatever splitTokens would make of it
	if quoteOutside(line) {
		return refuse(line, false, "a single quote outside double quotes (Junos does not quote with it)")
	}
	if reMarks.MatchString(line) || strings.Contains(line, "<SECRET>") {
		return refuse(line, false, "the line holds the mark of an elided secret, not a value")
	}
	toks := splitTokens(line)
	verb, path := toks[0], toks[1:]
	if verb == "insert" {
		path = path[:len(path)-3]
	}
	if len(path) == 0 {
		return refuse(line, false, "a statement with no path")
	}

	// the exact statements of the NETCONF setting (D147), when the rendering
	// states them: the one place under 'system services' a plan may write
	if netconfStatement(path) && a.netconfAllowed(line) {
		return nil
	}

	// the never list, whatever the tables say
	if id, ok := neverMatch(fam, Line{Text: line}); ok {
		return refuse(line, true, "on the never list (%s)", id)
	}
	for _, r := range allowNever {
		pre := strings.Fields(r.Pattern)
		if len(path) < len(pre) || !patternPrefix(pre, path) {
			continue
		}
		if r.Anywhere != "" && !slices.Contains(path[len(pre):], r.Anywhere) {
			continue
		}
		return refuse(line, true, "on the never list (%s): %s", r.ID, r.Why)
	}
	if a.Login != "" && len(path) >= 4 && slices.Equal(path[:3], []string{"system", "login", "user"}) && path[3] == a.Login {
		return refuse(line, true, "the invoking login's own user is never written")
	}

	if r, ok := abbreviated(path); ok {
		return refuse(line, true, "an abbreviation of %q, on the never list (%s): %s", r.Anywhere, r.ID, r.Why)
	}
	// the invoking login's class: a leaf of it may lock the login out
	if a.LoginClass != "" && len(path) >= 4 && slices.Equal(path[:3], []string{"system", "login", "class"}) && path[3] == a.LoginClass &&
		!a.rendered(line) {
		return refuse(line, true, "the invoking login's own class is never changed beyond what the rendering sets: a change may lock the login out")
	}

	// a list ('events [ login change-log ]') and the one-line forms of an NTP
	// server or key are as many statements as the device prints
	for _, p := range expandBrackets(path) {
		if err := a.hierarchy(line, verb, p); err != nil {
			return err
		}
	}
	return nil
}

// quoteOutside reports whether a single quote stands outside double quotes.
func quoteOutside(line string) bool {
	in, esc := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case esc:
			esc = false
		case in && c == '\\':
			esc = true
		case c == '"':
			in = !in
		case c == '\'' && !in:
			return true
		}
	}
	return false
}

// rendered reports whether every statement of the line, a list expanded, is
// one of the rendering's own 'set' lines.
func (a Allow) rendered(line string) bool {
	toks := splitTokens(line)
	if len(toks) < 2 || toks[0] != "set" {
		return false
	}
	have := map[string]bool{}
	for _, s := range a.Expected {
		for _, raw := range s.Lines {
			t := splitTokens(raw)
			if len(t) < 2 || t[0] != "set" {
				continue
			}
			for _, p := range expandBrackets(t[1:]) {
				have[strings.Join(p, "\x00")] = true
			}
		}
	}
	for _, p := range expandBrackets(toks[1:]) {
		if !have[strings.Join(p, "\x00")] {
			return false
		}
	}
	return true
}

// abbreviated reports a word of the path that is the beginning of a word a
// never row holds (Junos completes a unique abbreviation: 'auth' is
// 'authentication'), past the row's prefix. The word after 'class' is a
// class's name and is not held against it.
func abbreviated(path []string) (NeverRow, bool) {
	for _, r := range allowNever {
		pre := strings.Fields(r.Pattern)
		if r.Anywhere == "" || len(path) <= len(pre) || !patternPrefix(pre, path) {
			continue
		}
		for i := len(pre); i < len(path); i++ {
			w := path[i]
			if i > len(pre) && path[i-1] == "class" {
				continue
			}
			if w != "" && len(w) < len(r.Anywhere) && strings.HasPrefix(r.Anywhere, w) {
				return r, true
			}
		}
	}
	return NeverRow{}, false
}

// patternPrefix reports whether path starts with the words of pre ('?' any).
func patternPrefix(pre, path []string) bool {
	for i, p := range pre {
		if p != "?" && p != path[i] {
			return false
		}
	}
	return true
}

// hierarchy holds a path against the owned rows of the planned sections.
func (a Allow) hierarchy(line, verb string, path []string) error {
	// the planned sections that can be planned at all (netconf and
	// breakglass are never emitted, whatever a caller names)
	var sections []string
	for _, name := range PlanOrder(devconf.FamilyJunos) {
		if a.Sections == nil || slices.Contains(a.Sections, name) {
			sections = append(sections, name)
		}
	}
	var whole, additive, unnamed bool
	for _, name := range sections {
		var exp devices.Section
		for _, s := range a.Expected {
			if s.Name == name {
				exp = s
			}
		}
		for _, r := range junosRows(name, exp) {
			obj, at, ok := matchPrefix(r.pat, path)
			if !ok {
				continue
			}
			if at >= 0 && a.Expected != nil && !r.names[obj] {
				unnamed = true
				continue
			}
			if r.Depth > 0 && len(path) > r.Depth {
				// 'system accounting events login' and not what follows
				continue
			}
			if verb == string(OpDelete) {
				switch {
				case r.Mode == ModeAdditive || r.Mode == ModeSingle:
					// nothing under an additive list is ever deleted, and
					// a single-valued leaf is replaced by its set, never
					// deleted
					additive = true
					continue
				case r.Mode != ModeList && len(path) <= len(r.pat):
					// the object itself: the plan deletes what is inside
					// it, never a whole object (the helper's denyobj)
					whole = true
					continue
				}
			}
			return nil
		}
	}
	// a statement the rendering emits, though no table names its hierarchy
	if verb == string(OpSet) && a.Expected != nil {
		for _, name := range sections {
			for _, s := range a.Expected {
				if s.Name != name {
					continue
				}
				for _, raw := range s.Lines {
					if slices.Equal(splitTokens(raw), splitTokens(line)) {
						return nil
					}
				}
			}
		}
	}
	switch {
	case whole:
		return refuse(line, false, "deletes a whole object the rendering owns")
	case additive:
		return refuse(line, false, "deletes under a list the plan only adds to")
	case unnamed:
		return refuse(line, false, "names an object the rendering does not (a class or user that is not tacctl's)")
	case verb == string(OpDelete) && a.isAncestor(sections, path):
		return refuse(line, false, "deletes a whole hierarchy")
	}
	return refuse(line, false, "outside the hierarchies of the planned sections")
}

// isAncestor reports whether the path is shorter than an owned row it
// leads to ('delete snmp', 'delete system login').
func (a Allow) isAncestor(sections []string, path []string) bool {
	for _, name := range sections {
		for _, r := range junosOwned {
			pat := strings.Fields(r.Pattern)
			if r.Section == name && len(path) < len(pat) && patternPrefix(path, pat) {
				return true
			}
		}
	}
	return false
}

// CheckDelta holds every line of a delta against the allow-list, with the
// sections the delta plans. It returns the first refusal, with the line's
// number.
func (a Allow) CheckDelta(d Delta) error {
	if fam, _ := devconf.Family(d.Vendor); fam != devconf.FamilyJunos {
		return refuse("", false, "there is no allow-list for vendor %q", d.Vendor)
	}
	a.Vendor = d.Vendor
	a.Sections = d.Planned()
	if a.Sections == nil {
		a.Sections = []string{}
	}
	if len(d.Lines) > 0 {
		if err := a.Ready(); err != nil {
			return err
		}
	}
	for i, l := range d.Lines {
		if !slices.Contains(a.Sections, l.Section) {
			return refuse(l.Text, false, "line %d: its section %q is not planned", i+1, l.Section)
		}
		if err := a.Check(l.Text); err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return nil
}
