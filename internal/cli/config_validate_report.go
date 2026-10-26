package cli

// The model of 'config validate' (docs/plans/0.2.15-plan.md D219): the
// checks (configValidate, config_report.go) append the lines of the report
// and the findings they stand for to a validateReport, and the report is
// printed from it: as text, line by line as the checks go, the way 0.1.16
// printed it, or as the JSON object of D220 once they are done.

import "strconv"

// The levels of a finding. An error is a finding that counts toward the
// exit status; a warning never does, whatever colour the text report gives
// its line.
const (
	levelError   = "error"
	levelWarning = "warning"
)

// validateSections are the tokens a finding's section takes, one per label
// of the text report (D220), in the order the report first reaches them.
var validateSections = []string{
	"store", "yaml", "overrides", "command_rules", "structure", "scope_default",
	"linux_hosts", "names", "breakglass", "breakglass_hold", "emergency_lockdown", "config_blocks",
	"operator_policy", "group_settings", "orphan_settings", "orphan_files",
	"leftovers", "backends", "rendered", "drift", "vendor_attrs",
}

// validateFinding is one thing the report says is wrong.
type validateFinding struct {
	Section string `json:"section"`
	Level   string `json:"level"`
	Backend string `json:"backend,omitempty"`
	// Text is the finding without the command that puts it right, which
	// is Fix when the finding carries one apart from its text.
	Text  string   `json:"text"`
	Fix   string   `json:"fix"`
	Hosts []string `json:"hosts,omitempty"`

	// Kind, Name, To and Verb are what a 'names' finding says to rename
	// (hostFinding): 'config validate --fix-names' reads them.
	Kind, Name, To, Verb string `json:"-"`

	// repeat is set on the second and later drifted artifacts of one
	// block: the text report counts a block of them as one error.
	repeat bool
}

// validateHow is how the text report prints an item.
type validateHow int

const (
	// howEcho is inv.echo (the line as it is), howEchoE inv.echoE (its
	// backslash escapes interpreted), howRaw inv.write (the text, which ends
	// its own lines).
	howEcho validateHow = iota
	howEchoE
	howRaw
	// howErrorE is the line on standard error as out.ErrorE prints it, and
	// howModelErr the model's load error as reportModelError prints it.
	howErrorE
	howModelErr
)

// validateItem is one thing the text report prints, in the order the checks
// reach it, and the finding it is, if it is one.
type validateItem struct {
	how     validateHow
	text    string
	err     error
	finding *validateFinding
}

// validateReport is what 'config validate' found: the items of its text
// report in order, which sections it could count, and the backends it went
// through.
type validateReport struct {
	items []validateItem
	// sink is told of each item as it is added: the text report prints
	// there, so a slow check is not waited for with nothing on the screen.
	sink func(validateItem)

	storeMode bool
	// counts are the groups, scopes and users the model has ("?" when it
	// could not be read).
	counts map[string]string
	// backends are the enabled backends (none when the list cannot be read).
	backends []string
}

// add appends an item, with the finding it is (nil for a line that is not
// one).
func (r *validateReport) add(how validateHow, text string, f *validateFinding) {
	it := validateItem{how: how, text: text, finding: f}
	r.items = append(r.items, it)
	if r.sink != nil {
		r.sink(it)
	}
}

// line adds a line of the report that is not a finding.
func (r *validateReport) line(how validateHow, text string) { r.add(how, text, nil) }

// found adds a line of the report that is a finding.
func (r *validateReport) found(how validateHow, text string, f validateFinding) {
	r.add(how, text, &f)
}

// modelErr adds the model's load error, which the text report prints on
// standard error.
func (r *validateReport) modelErr(err error) {
	it := validateItem{how: howModelErr, err: err}
	r.items = append(r.items, it)
	if r.sink != nil {
		r.sink(it)
	}
}

// findings are the findings in the order they were found.
func (r *validateReport) findings() []validateFinding {
	var out []validateFinding
	for _, it := range r.items {
		if it.finding != nil {
			out = append(out, *it.finding)
		}
	}
	return out
}

// errors and warnings count the findings of each level.
func (r *validateReport) errors() int   { return r.count(levelError, false) }
func (r *validateReport) warnings() int { return r.count(levelWarning, false) }

// textErrors is the count the text report states: a block of drifted
// artifacts is one error.
func (r *validateReport) textErrors() int { return r.count(levelError, true) }

func (r *validateReport) count(level string, text bool) int {
	n := 0
	for _, it := range r.items {
		if f := it.finding; f != nil && f.Level == level && (!text || !f.repeat) {
			n++
		}
	}
	return n
}

// printValidateText is the text report's sink: the item as the report
// prints it.
func (inv *invocation) printValidateText(it validateItem) {
	switch it.how {
	case howEcho:
		inv.echo(it.text)
	case howEchoE:
		inv.echoE(it.text)
	case howRaw:
		inv.write(it.text)
	case howErrorE:
		inv.app.Out.ErrorE(it.text)
	case howModelErr:
		inv.reportModelError(it.err)
	}
}

// printValidateTextEnd is the end of the text report: the blank line, then
// the verdict.
func (inv *invocation) printValidateTextEnd(r *validateReport) {
	out := inv.app.Out
	inv.echo("")
	if errs := r.textErrors(); errs > 0 {
		out.Error("Validation failed with " + strconv.Itoa(errs) + " error(s).")
		return
	}
	out.Info("Configuration is valid.")
	inv.echo("")
}

// validateJSON is the object 'config validate --json' prints (D220).
type validateJSON struct {
	Valid    bool              `json:"valid"`
	Errors   int               `json:"errors"`
	Warnings int               `json:"warnings"`
	Mode     string            `json:"mode"`
	Counts   *validateCounts   `json:"counts"`
	Backends []string          `json:"backends"`
	Findings []validateFinding `json:"findings"`
}

// validateCounts are the users, groups and scopes the store defines.
type validateCounts struct {
	Users  int `json:"users"`
	Groups int `json:"groups"`
	Scopes int `json:"scopes"`
}

// printValidateJSONItem is the JSON report's sink: the report goes to standard
// output at the end, so what the checks write around themselves (the model's
// complaint) is the only thing printed as they go, on standard error.
func (inv *invocation) printValidateJSONItem(it validateItem) {
	if it.how == howModelErr {
		inv.reportModelError(it.err)
	}
}

// configValidateJSON runs the checks and prints the object of D220; the exit
// status is the text report's: 1 when a finding is an error.
func (inv *invocation) configValidateJSON() error {
	r := &validateReport{sink: inv.printValidateJSONItem}
	inv.collectValidate(r)
	out := validateJSON{
		Valid:    r.errors() == 0,
		Errors:   r.errors(),
		Warnings: r.warnings(),
		Mode:     "legacy",
		Counts:   r.countsJSON(),
		Backends: r.backends,
		Findings: r.findings(),
	}
	if r.storeMode {
		out.Mode = "store"
	}
	if out.Backends == nil {
		out.Backends = []string{}
	}
	if out.Findings == nil {
		out.Findings = []validateFinding{}
	}
	if err := inv.printJSON(out); err != nil {
		return err
	}
	if out.Errors > 0 {
		return exit(1)
	}
	return nil
}

// countsJSON are the counts of the model, nil when it could not be read.
func (r *validateReport) countsJSON() *validateCounts {
	var c validateCounts
	for k, p := range map[string]*int{"users": &c.Users, "groups": &c.Groups, "scopes": &c.Scopes} {
		n, err := strconv.Atoi(r.counts[k])
		if err != nil {
			return nil
		}
		*p = n
	}
	return &c
}
