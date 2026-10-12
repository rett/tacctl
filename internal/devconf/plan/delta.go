// Package plan turns the comparison of a pulled device (devconf.Compare)
// into the statements that take it from what it runs to what tacctl renders,
// and into the text a person pastes (docs/plans/0.2.5-plan.md D94-D107).
//
// The package is pure: no clock, no network, no global state. Every time, the
// tool version and everything "from the record" is an input.
//
// The planner (Plan) works from the comparison's '-' (missing), '+' (extra)
// and '!' (out of order) lines of the managed sections, under the ownership
// tables of owned.go (apply-deferred.md D79):
//
//   - a missing statement is set; a single-valued leaf with another value is
//     replaced by the same set, never deleted;
//   - an extra statement is deleted only when it is an element of an object
//     tacctl renders whole (owned.go); every other extra is kept and listed;
//   - a statement that comes from a group is never changed, the section that
//     would have to is refused;
//   - a secret is pasted by value when the device lacks it, and otherwise
//     neither printed nor changed unless Options.Secrets (D80, D98).
//
// The emitters (Block, Plain, JSON) are in emit*.go, the in-memory editors
// the property test applies a Delta with in simulate.go.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Op is what a Line does.
type Op string

// The ops: Junos set, delete and insert; IOS line (type the line) and no
// (type 'no <line>').
const (
	OpSet    Op = "set"
	OpDelete Op = "delete"
	OpInsert Op = "insert"
	OpLine   Op = "line"
	OpNo     Op = "no"
	// OpComment is a back-out step that cannot be a line ("re-enter the
	// original key"); only Undo lines have it.
	OpComment Op = "comment"
)

// Line is one statement of a Delta, in paste order.
type Line struct {
	// Section is the managed section the line belongs to.
	Section string `json:"-"`
	Op      Op     `json:"op"`
	// Text is what is pasted: a whole Junos statement ('set ...', 'delete
	// ...', 'insert ...'), an IOS line without its indentation. For a secret
	// it holds the value (HasValue), or the placeholder under --no-secrets.
	Text string `json:"text"`
	// Context is an IOS line's submode headers, outermost first.
	Context []string `json:"-"`
	// Secret marks a statement that carries a secret.
	Secret bool `json:"secret"`
	// HasValue is set when Text holds the secret's value. Display and the
	// JSON never show Text of such a line: they show Elided.
	HasValue bool `json:"-"`
	// Elided is Text with the secret's value left out ('<secret>' in its
	// place); empty for a line that is not a secret.
	Elided string `json:"-"`
	// Undo are the lines that put back what this one changed (IOS only: the
	// back-out block is built from them).
	Undo []Line `json:"-"`
	// For are the compared statements (stems, '!' texts) this line is the
	// answer to: the report says "fixed by region line N" from them.
	For []string `json:"-"`
	// Late marks a line the block puts after every other section (IOS: the
	// command authorization of the aaa unit, which must not be on while the
	// rest is typed).
	Late bool `json:"-"`
	// Leaf marks the login method of a console or vty line (IOS), which the
	// block types after roles, snmp and mgmt-acl and before the command
	// authorization (D118 (9)).
	Leaf bool `json:"-"`
}

// String is the line as Shown: a secret's value never reaches a %v or %s.
func (l Line) String() string {
	s := l.Shown()
	switch l.Op {
	case OpNo:
		s = "no " + s
	case OpComment:
		s = "(" + s + ")"
	}
	if len(l.Context) > 0 {
		s = strings.Join(l.Context, " > ") + " > " + s
	}
	return s
}

// Format elides too, for every verb (%v, %+v, %#v, %q): the value of a
// secret line is in Text and only Text.
func (l Line) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", l.String())
	default:
		_, _ = fmt.Fprint(f, l.String())
	}
}

// String is Display.
func (d Delta) String() string { return d.Display() }

// Format prints a Delta as Display for every verb: its lines hold values
// and its record of the running configuration holds more.
func (d Delta) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", d.Display())
	default:
		_, _ = fmt.Fprint(f, d.Display())
	}
}

// MarshalJSON writes the line with its secret value elided: whatever
// marshals a Line cannot leak one.
func (l Line) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Op     Op     `json:"op"`
		Text   string `json:"text"`
		Secret bool   `json:"secret"`
	}{l.Op, l.Shown(), l.Secret})
}

// Shown is the line as a person may see it anywhere but in a paste block:
// a secret's value elided.
func (l Line) Shown() string {
	if l.Secret && l.Elided != "" {
		return l.Elided
	}
	return l.Text
}

// Kept is a statement of a managed hierarchy that is left as it is.
type Kept struct {
	Section string `json:"section"`
	// Text is the statement, a secret's value elided.
	Text string `json:"text"`
	Note string `json:"note,omitempty"`
}

// The kinds of Skip, so a caller does not tell them apart by text.
const (
	// KindRefused: the plan refuses the section because emitting it could
	// lock the person out or change what a group owns (inherited, the
	// filter's --from, the aaa unit's guards). A caller exits 1.
	KindRefused = "refused"
	// KindClassSkip: the caller's class cannot see what the section holds.
	KindClassSkip = "class"
	// KindNotWritable: the caller named the section as not writable.
	KindNotWritable = "not-writable"
	// KindNotPlannable: the record cannot be planned from until a new pull.
	KindNotPlannable = "not-plannable"
)

// Skip is a section (or part of one) the plan leaves out, with the reason.
type Skip struct {
	Section string `json:"section"`
	// Kind is one of the Kind constants.
	Kind string `json:"kind"`
	Why  string `json:"why"`
}

// The states of a section in a plan.
const (
	// StatePlanned: the section has statements in the block.
	StatePlanned = "planned"
	// StateNoChange: the device already has everything the section renders.
	StateNoChange = "no change"
	// StateNA: tacctl renders nothing for the section.
	StateNA = "not rendered"
	// StateSkipped: the section is left out with a reason (a refusal, the
	// caller's class).
	StateSkipped = "skipped"
	// StateNotSelected: the section was not named by --section.
	StateNotSelected = "not selected"
	// StateNotVisible: the pull's login could not read what the section
	// compares, so nothing can be said.
	StateNotVisible = "not visible"
	// StateNever: the section is never emitted (netconf, breakglass).
	StateNever = "never emitted"
)

// SectionPlan is the plan's word on one managed section.
type SectionPlan struct {
	Name  string `json:"name"`
	State string `json:"state"`
	// Kind is the kind of a skipped section (see KindRefused).
	Kind string `json:"kind,omitempty"`
	// Why is the one-line reason of a planned section (the comment above its
	// statements) or the reason a section is skipped.
	Why string `json:"why,omitempty"`
	// Statements counts the section's lines in the block.
	Statements int `json:"statements"`
}

// Counts summarises a Delta.
type Counts struct {
	Set, Delete, Insert, Line, No int
	Kept                          int
	// SecretsPresent counts secret statements the device has and the plan
	// does not change; SecretsNotVisible those its pull could not read.
	SecretsPresent    int
	SecretsNotVisible int
	// SecretsByValue counts the lines that hold a value, Placeholders those
	// that hold '<SECRET>'.
	SecretsByValue int
	Placeholders   int
}

// Delta is the plan of one device.
type Delta struct {
	// Vendor is the family the plan is for (devconf.FamilyJunos or
	// devconf.FamilyIOS).
	Vendor string
	// Lines are the statements in paste order, grouped by section in the
	// order of PlanOrder.
	Lines []Line
	// Kept are the statements of the managed hierarchies the plan leaves.
	Kept []Kept
	// Skipped are the sections (or parts of one) left out, with the reason.
	Skipped []Skip
	// Inherited are the statements, a secret's value elided, that come from
	// a group and would have had to change.
	Inherited []string
	// Sections has every managed section, in PlanOrder then the two that are
	// never emitted.
	Sections []SectionPlan
	Counts   Counts
	// Warnings are the findings the header names and the block still
	// carries. Notes are comparison findings that are not drift.
	Warnings []string
	Notes    []string
	// Unattributed are statements under an SNMP community whose name the
	// comparison elides (it is the secret): a delete line acts on the
	// rendered community only, so these may stay on the device.
	Unattributed []string
	// Withheld are statements the plan did not emit because the caller's
	// class cannot see their hierarchy (see Class), or because they are the
	// operator's step (the IOS access-class binding), or because the
	// device's TACACS+ path is not proven yet (the IOS command-authorization
	// lines, D118 (12)), elided.
	Withheld []string
	// InheritanceChecked is false when no plain view was given: the plan
	// then could not tell a group's statements from the device's own.
	InheritanceChecked bool
	// SecretKinds are the kinds of secret the block holds by value, for the
	// header's sensitivity line.
	SecretKinds []string
	// Scope is the scope's name for the sensitivity line, from Options.
	Scope string
	// BreakglassHeld is Options.BreakglassHeld: the device is held for
	// break-glass.
	BreakglassHeld *BreakglassHold
	// Syntax is Options.Syntax (SyntaxIOS12 or SyntaxModern; empty on
	// Junos).
	Syntax string
	// Login are the IOS vty and console login leaves the back-out restores.
	Login []LoginLeaf
	// AddsAAA is true when the block turns 'aaa new-model' on.
	AddsAAA bool
	// Backout are the Junos lines that put the planned sections back to
	// what the pull showed (set, delete, insert, and OpComment lines for
	// what cannot be typed: an original secret). An IOS delta has none: its
	// back-out is built from the undo lines of Lines.
	Backout []Line
	// Class is the caller's class name when it limited the plan.
	Class string
	// ByHand are the steps a person types by hand, from the console, for a
	// unit the plan refuses (D117: the legacy server form with command
	// authorization); they are outside any region.
	ByHand []string
	// Items are the irregularities of the comparison, in plain words, in
	// the order of the report (D110); Extras the statements left alone, each
	// with the exact removal line (D111), so a cleanup region can be added.
	Items  []Item
	Extras []Extra
	// Converge is set when the plan was asked for the cleanup (--converge),
	// and Cleanup is that second region (empty when there is nothing to
	// remove or the cleanup is refused: Cleanup.Whole says why).
	Converge bool
	Cleanup  Cleanup
}

// Severity of an irregularity (D110).
const (
	SevAccess     = "ACCESS"
	SevMonitoring = "MONITORING"
	SevCosmetic   = "COSMETIC"
)

// The kinds of irregularity (D110).
const (
	KindMissing   = "missing"
	KindDifferent = "different"
	KindOrder     = "out of order"
	KindExtra     = "extra"
	KindSecret    = "secret not visible"
	KindNotPlan   = "not plannable for this login"
	// KindNoLocal: the device has no local user at privilege 15 and the
	// paste puts AAA in front of the local database (M4).
	KindNoLocal = "no local login"
)

// Item is one irregularity: one finding of the comparison.
type Item struct {
	N        int    `json:"n"`
	Kind     string `json:"kind"`
	Section  string `json:"section"`
	Severity string `json:"severity"`
	// Words is the finding in plain words; Statement the compared line, a
	// secret's value elided.
	Words     string `json:"what"`
	Statement string `json:"statement"`
	// Action is what the paste does about it.
	Action string `json:"action"`
	// Lines are indexes into Delta.Lines of the lines that fix it.
	Lines []int `json:"-"`
	// Fixed says the paste fixes it (Lines is not empty).
	Fixed bool `json:"fixed"`
	// n counts the findings folded into the item.
	n int
}

// removedByCleanup reports an extra that the cleanup region removes.
func (it Item) removedByCleanup() bool {
	return !it.Fixed && strings.HasPrefix(it.Action, "Removed by the cleanup region")
}

// Extra is a statement of a standard hierarchy that the standard does not
// have, left alone by the paste (D111). Remove is the exact line that
// removes it, empty when Guard says why tacctl does not offer one.
type Extra struct {
	Section string `json:"section"`
	Text    string `json:"text"`
	Remove  []Line `json:"remove,omitempty"`
	Guard   string `json:"guard,omitempty"`
}

// Display is the delta as text with every secret's value elided: one
// statement per line, grouped under '[section]' headers. It is the form
// logs, errors and tests may hold.
func (d Delta) Display() string {
	var b strings.Builder
	cur := ""
	for _, l := range d.Lines {
		if l.Section != cur {
			cur = l.Section
			fmt.Fprintf(&b, "[%s]\n", cur)
		}
		for i, c := range l.Context {
			b.WriteString(strings.Repeat(" ", i) + c + "\n")
		}
		text := l.Shown()
		if l.Op == OpNo {
			text = "no " + text
		}
		b.WriteString(strings.Repeat(" ", len(l.Context)) + text + "\n")
	}
	return b.String()
}

// Equal reports whether two deltas hold the same statements in the same
// order (secret values included: it is what the deferred apply compares
// between a review and the run).
func (d Delta) Equal(o Delta) bool {
	if len(d.Lines) != len(o.Lines) {
		return false
	}
	for i, l := range d.Lines {
		m := o.Lines[i]
		if l.Section != m.Section || l.Op != m.Op || l.Text != m.Text || !slices.Equal(l.Context, m.Context) {
			return false
		}
	}
	return true
}

// Empty reports whether the delta has no statement to paste.
func (d Delta) Empty() bool { return len(d.Lines) == 0 }

// HoldsSecret reports whether a line of the delta holds a secret's value.
func (d Delta) HoldsSecret() bool { return d.Counts.SecretsByValue > 0 }

// Of returns the plan's word on a section (a zero value when unknown).
func (d Delta) Of(section string) SectionPlan {
	for _, s := range d.Sections {
		if s.Name == section {
			return s
		}
	}
	return SectionPlan{Name: section}
}

// Planned lists the sections that have statements, in order.
func (d Delta) Planned() []string {
	var out []string
	for _, s := range d.Sections {
		if s.State == StatePlanned {
			out = append(out, s.Name)
		}
	}
	return out
}

// Errors of Plan.
var (
	// ErrUnsupported: the vendor has no planner (wti, in this release).
	ErrUnsupported = errors.New("plan: no planner for this vendor")
	// ErrNeverEmitted: --section named a section that is never emitted.
	ErrNeverEmitted = errors.New("plan: the section is never emitted")
	// ErrUsage: contradictory options.
	ErrUsage = errors.New("plan: wrong options")
)
