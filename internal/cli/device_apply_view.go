package cli

// The output of 'device config apply': one line per device and phase, the
// review (grouped by shape, secrets elided, one typed answer), the summary
// and the exit status (docs/plans/0.2.9-rollout-plan.md section 3.3, D134).
// The batch runner calls the view from one goroutine only.

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

// applyView is the batch.View of one phase.
type applyView struct {
	batch.Board
	inv    *invocation
	out    io.Writer
	enc    *json.Encoder
	phase  string
	json   bool
	user   string
	names  []string
	scopes []string
	vendor []string
	width  int
}

// newApplyView is the view of a phase over entries.
func (inv *invocation) newApplyView(entries []devreg.Entry, phase string, asJSON bool, user string) *applyView {
	v := &applyView{inv: inv, out: inv.app.Out.Stdout, phase: phase, json: asJSON, user: user}
	for _, e := range entries {
		v.names = append(v.names, e.Name)
		v.scopes = append(v.scopes, e.Scope)
		v.vendor = append(v.vendor, e.Vendor)
		v.width = max(v.width, len(e.Name))
	}
	v.enc = json.NewEncoder(v.out)
	return v
}

// Begin queues every device (nothing is printed: the lines come as devices
// end).
func (v *applyView) Begin(names []string) { v.Board.Begin(names) }

// Update shows one device's change: a progress step of a running apply, or
// the line of a device that ended.
func (v *applyView) Update(e batch.Event) {
	v.Board.Update(e)
	switch e.Phase {
	case batch.PhaseRunning:
		return
	case batch.PhaseProgress:
		if !v.json && e.Step != "" {
			_, _ = fmt.Fprintf(v.out, "  %-*s  %s ...\n", v.width, v.names[e.Index], e.Step)
		}
		return
	}
	o, _ := e.Result.Value.(*applyOutcome)
	if o != nil && e.Phase == batch.PhaseDone {
		v.audit(o)
	}
	if v.json {
		_ = v.enc.Encode(v.deviceJSON(e.Index, o, e.Result))
		return
	}
	text := e.Result.Text()
	if o != nil {
		text = o.line()
	}
	_, _ = fmt.Fprintf(v.out, "  %-*s  %s\n", v.width, v.names[e.Index], cleanLine(text))
}

// End leaves the lines as they are; the verb prints the summary.
func (v *applyView) End(s batch.Summary) { v.Board.End(s) }

// audit logs a finished device (D141): never a value, never a reason's text.
func (v *applyView) audit(o *applyOutcome) {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	id, shape := "-", "-"
	var dur = o.Duration
	if o.Out != nil {
		id, shape = dash(o.Out.ID), dash(o.Out.Shape)
	}
	if v.phase == "check" {
		v.inv.app.Logger(v.inv.auditContext(), "auth.info", fmt.Sprintf("device config apply user=%s device=%s id=%s shape=%s result=%s duration=%s",
			v.user, o.Name, id, shape, o.word(), seconds(dur)))
		return
	}
	sections, commit, until := "-", "-", "-"
	if o.Out != nil {
		if len(o.Out.Sections) > 0 {
			sections = strings.Join(o.Out.Sections, ",")
		}
		if o.Out.Commit != nil {
			commit = strconv.Itoa(o.Out.Commit.Seq)
		}
		if !o.Out.Until.IsZero() {
			until = o.Out.Until.UTC().Format(time.RFC3339)
		}
	}
	v.inv.app.Logger(v.inv.auditContext(), "auth.notice", fmt.Sprintf("device config apply user=%s device=%s id=%s shape=%s sections=%s result=%s commit=%s until=%s",
		v.user, o.Name, id, shape, sections, o.word(), commit, until))
}

// line is the device's line of its phase.
func (o *applyOutcome) line() string {
	var s string
	switch {
	case o.Status == "not-started":
		s = "not started"
	case o.Skipped != "":
		s = "skipped: " + o.Skipped
	case o.Out == nil:
		s = "failed: " + o.reason()
		if o.Status == "unsupported" {
			s = "unsupported: " + o.reason()
		}
		if o.Hint != "" && o.Status == "" {
			s += " (" + o.Hint + ")"
		}
	case o.Out.Exit == devapply.ExitChecked:
		s = o.checkedLine()
	default:
		s = o.Out.Line()
		if o.Out.Exit == devapply.ExitPending || o.Out.Exit == devapply.ExitWindowShort || o.Out.Exit == devapply.ExitUnknown {
			s = ui.Red + s + ui.NC
		}
	}
	if o.RecordErr != "" {
		s += " (the record was not kept: " + o.RecordErr + ")"
	}
	return s
}

// counts is "n set, m delete[, k insert]".
func (o *applyOutcome) counts() string {
	c := fmt.Sprintf("%d set, %d delete", o.Out.Counts.Set, o.Out.Counts.Delete)
	if o.Out.Counts.Insert > 0 {
		c += fmt.Sprintf(", %d insert", o.Out.Counts.Insert)
	}
	return c
}

// checkedLine is the line of a device whose check ended (plan 3.3).
func (o *applyOutcome) checkedLine() string {
	shape := "no shape"
	if o.Out.Shape != "" {
		shape = "shape " + o.Out.Shape
		if o.ConfirmedOn != "" {
			shape += " (confirmed on " + o.ConfirmedOn + ")"
		} else {
			shape += " (new)"
		}
	}
	s := fmt.Sprintf("checked: %s (%s: %s)", shape, strings.Join(o.Out.Sections, ", "), o.counts())
	if n := len(o.Delta.Kept); n > 0 {
		s += fmt.Sprintf("; kept %d", n)
	}
	return s + "; check ok"
}

// --- JSON ----------------------------------------------------------------------

// applyJSON is one device of one phase in --json.
type applyJSON struct {
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Vendor    string   `json:"vendor"`
	Phase     string   `json:"phase"`
	Status    string   `json:"status"`
	Result    string   `json:"result,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	ID        string   `json:"id,omitempty"`
	Shape     string   `json:"shape,omitempty"`
	Confirmed string   `json:"confirmed_on,omitempty"`
	Sections  []string `json:"sections,omitempty"`
	Set       int      `json:"set,omitempty"`
	Delete    int      `json:"delete,omitempty"`
	Insert    int      `json:"insert,omitempty"`
	NotFound  int      `json:"not_found,omitempty"`
	Until     string   `json:"until,omitempty"`
	Commit    *struct {
		Seq  int    `json:"seq,omitempty"`
		Time string `json:"time,omitempty"`
	} `json:"commit,omitempty"`
	// Lines are the statements of the change, a secret's value elided.
	Lines      []string `json:"lines,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// deviceJSON is the object of one device's event.
func (v *applyView) deviceJSON(i int, o *applyOutcome, res batch.Result) applyJSON {
	j := applyJSON{Name: v.names[i], Scope: v.scopes[i], Vendor: v.vendor[i], Phase: v.phase, Status: res.Status.String()}
	if o == nil {
		j.Reason = cleanLine(res.Reason)
		return j
	}
	return o.json(j)
}

// json fills the object from the outcome.
func (o *applyOutcome) json(j applyJSON) applyJSON {
	j.Name, j.Scope, j.Vendor, j.Phase = o.Name, o.Scope, o.Vendor, o.Phase
	j.Status = o.word()
	j.Confirmed, j.DurationMS = o.ConfirmedOn, o.Duration.Milliseconds()
	switch {
	case o.Skipped != "":
		j.Reason = cleanLine(o.Skipped)
	case o.Out == nil:
		j.Reason = cleanLine(o.reason())
	}
	if o.Out != nil {
		out := o.Out
		j.Result, j.ID, j.Shape, j.Sections = string(out.Result), out.ID, out.Shape, out.Sections
		j.Set, j.Delete, j.Insert, j.NotFound = out.Counts.Set, out.Counts.Delete, out.Counts.Insert, out.Counts.NotFound
		if out.Reason != "" && j.Reason == "" {
			j.Reason = cleanLine(out.Reason)
		}
		if !out.Until.IsZero() {
			j.Until = out.Until.UTC().Format(time.RFC3339)
		}
		if out.Commit != nil {
			j.Commit = &struct {
				Seq  int    `json:"seq,omitempty"`
				Time string `json:"time,omitempty"`
			}{out.Commit.Seq, out.Commit.TimeText}
		}
		if out.Exit == devapply.ExitChecked {
			for _, l := range o.Delta.Lines {
				j.Lines = append(j.Lines, l.Shown())
			}
		}
	}
	return j
}

// --- the review ------------------------------------------------------------------

// shapeGroup is the devices that need the same change.
type shapeGroup struct {
	hash    string
	devices []*applyOutcome
	// confirmedOn is the device that confirmed the shape ("" a new shape).
	confirmedOn string
}

// groupByShape groups the checked devices by shape, in the order of their
// first device (D134).
func (c *applyCtl) groupByShape(junos []devreg.Entry, byName map[string]*applyOutcome) []*shapeGroup {
	var groups []*shapeGroup
	idx := map[string]*shapeGroup{}
	for _, e := range junos {
		o := byName[strings.ToLower(e.Name)]
		if o == nil || o.Out == nil || o.Out.Exit != devapply.ExitChecked || !o.HasDelta {
			continue
		}
		g := idx[o.Out.Shape]
		if g == nil || o.Out.Shape == "" {
			g = &shapeGroup{hash: o.Out.Shape}
			groups = append(groups, g)
			if o.Out.Shape != "" {
				idx[o.Out.Shape] = g
			}
		}
		g.devices = append(g.devices, o)
	}
	return groups
}

// selectApply decides which of the checked devices go on to Phase B: with
// --confirmed only the shapes a verified apply confirmed (the rest skipped,
// D135), then at most --max in registry order (D139). It sets each device's
// Skipped reason and returns the devices to apply.
func (c *applyCtl) selectApply(groups []*shapeGroup, byName map[string]*applyOutcome) []*applyOutcome {
	known, _ := c.run.shapes.Load()
	var eligible []*applyOutcome
	for _, g := range groups {
		if ent, ok := known[g.hash]; ok && g.hash != "" && len(ent.Confirmed) > 0 {
			g.confirmedOn = ent.Confirmed[0].Device
		}
		for _, o := range g.devices {
			o.ConfirmedOn = g.confirmedOn
			if c.aa.confirmed && g.confirmedOn == "" {
				if g.hash == "" {
					o.Skipped = "no shape: the change cannot be matched to a confirmed one; review and apply it by hand first"
				} else {
					o.Skipped = "unknown shape " + g.hash + ": review and apply it by hand first"
				}
				continue
			}
			eligible = append(eligible, o)
		}
	}
	// the registry's order, the order the devices were selected in
	order := map[*applyOutcome]int{}
	n := 0
	for _, o := range c.rows {
		order[o] = n
		n++
	}
	for i := 1; i < len(eligible); i++ {
		for j := i; j > 0 && order[eligible[j]] < order[eligible[j-1]]; j-- {
			eligible[j], eligible[j-1] = eligible[j-1], eligible[j]
		}
	}
	if len(eligible) > c.aa.max {
		for _, o := range eligible[c.aa.max:] {
			o.Skipped = "beyond --max " + strconv.Itoa(c.aa.max) + ": run it again for the rest"
		}
		eligible = eligible[:c.aa.max]
	}
	return eligible
}

// review prints the groups and asks the one question (D134); it reports
// whether the apply goes on. Nothing is asked of a run that was given
// --yes (it needs --confirmed: every shape is one that was confirmed).
func (c *applyCtl) review(groups []*shapeGroup, apply []*applyOutcome, asJSON bool) bool {
	inv := c.inv
	w := inv.app.Out.Stdout
	if asJSON {
		w = inv.app.Out.Stderr
	}
	pf := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	inApply := map[*applyOutcome]bool{}
	for _, o := range apply {
		inApply[o] = true
	}
	pf("\n")
	for _, g := range groups {
		first := g.devices[0]
		names := make([]string, len(g.devices))
		for i, o := range g.devices {
			names[i] = o.Name
		}
		state := "not confirmed yet"
		if g.confirmedOn != "" {
			state = "confirmed on " + g.confirmedOn
		}
		head := "Shape " + g.hash
		if g.hash == "" {
			head = "No shape"
		}
		pf("%s, %s (%s), %s:\n", head, howMany(len(g.devices), "device"), strings.Join(names, ", "), state)
		d := first.Delta
		cur := ""
		for _, l := range d.Lines {
			if l.Section != cur {
				cur = l.Section
				why := d.Of(cur).Why
				if why != "" {
					pf("  %-8s %s\n", cur, cleanLine(why))
				} else {
					pf("  %s\n", cur)
				}
			}
			pf("    %s\n", cleanLine(l.Shown()))
		}
		for _, w2 := range d.Warnings {
			pf("  warning: %s\n", cleanLine(w2))
		}
		for _, s := range d.Skipped {
			pf("  not planned: %s: %s\n", s.Section, cleanLine(s.Why))
		}
		if n := len(d.Kept); n > 0 {
			pf("  kept: %s of the managed sections that the plan leaves alone\n", howMany(n, "statement"))
			for i, k := range d.Kept {
				if i >= 5 {
					pf("    ... and %d more\n", n-5)
					break
				}
				pf("    %s\n", cleanLine(k.Text))
			}
		}
		if first.Out != nil && first.Out.Counts.NotFound > 0 {
			pf("  %s answered 'statement not found' (nothing to delete: not a failure)\n", howMany(first.Out.Counts.NotFound, "delete"))
		}
		pf("\n")
	}
	// the devices left out of the apply, as the rows of the others
	width := 0
	for _, g := range groups {
		for _, o := range g.devices {
			width = max(width, len(o.Name))
		}
	}
	for _, g := range groups {
		for _, o := range g.devices {
			if inApply[o] {
				continue
			}
			if asJSON {
				j := o.json(applyJSON{})
				j.Phase = "apply"
				_ = json.NewEncoder(inv.app.Out.Stdout).Encode(j)
			} else {
				pf("  %-*s  skipped: %s\n", width, o.Name, cleanLine(o.Skipped))
			}
		}
	}
	if len(apply) == 0 {
		return false
	}
	// A shape has one first device that runs alone (the canary) unless
	// --no-canary asks for the rest at once.
	how := ", one shape's first device at a time, each"
	if c.aa.noCanary {
		how = ", all at once, each"
	}
	if len(apply) == 1 {
		how = ""
	}
	hold := ""
	if c.aa.hold {
		hold = ", and held for your word after the fresh login"
	}
	names := make([]string, len(apply))
	for i, o := range apply {
		names[i] = o.Name
	}
	target := fmt.Sprintf("%s (%s)", howMany(len(apply), "device"), strings.Join(names, ", "))
	if len(apply) == 1 {
		target = names[0]
	}
	q := fmt.Sprintf("Apply to %s%s under commit confirmed %d and kept only after a fresh login as %s works and what landed is what the check showed%s?",
		target, how, c.run.minutes, c.user, hold)
	if c.aa.yes {
		pf("%s\n  --yes: every shape is one another device confirmed; going on.\n", q)
		c.audit(apply, names)
		return true
	}
	want := strconv.Itoa(len(apply))
	ask := "Type " + want + " to go on: "
	if len(apply) == 1 {
		want = apply[0].Name
		ask = "Type the device name to go on: "
	}
	pf("%s\n", q)
	if got := inv.app.Prompter().Ask("  " + ask); got != want {
		inv.app.Out.ErrorE("The answer typed is not '" + want + "'. Nothing was changed.")
		return false
	}
	c.audit(apply, names)
	return true
}

// audit logs the approval: how many, which shapes, which canary.
func (c *applyCtl) audit(apply []*applyOutcome, names []string) {
	var shapes []string
	for _, o := range apply {
		if o.Out != nil && o.Out.Shape != "" && !contains(shapes, o.Out.Shape) {
			shapes = append(shapes, o.Out.Shape)
		}
	}
	list := "-"
	if len(shapes) > 0 {
		list = strings.Join(shapes, ",")
	}
	c.inv.app.Logger(c.inv.auditContext(), "auth.notice", fmt.Sprintf("device config apply user=%s approved=%d shapes=%s canary=%s",
		c.user, len(apply), list, names[0]))
}

// --- the summary -----------------------------------------------------------------

// tally counts the devices by the word of their final outcome.
func (c *applyCtl) tally() map[string]int {
	m := map[string]int{}
	for _, o := range c.rows {
		m[o.word()]++
	}
	return m
}

// summaryLine is the one-line count of the final words.
func summaryLine(m map[string]int) string {
	var parts []string
	for _, w := range []struct{ key, text string }{
		{"applied", "applied"}, {"applied-by-other", "applied by someone else's commit"}, {"checked", "checked"},
		{"no-change", "no change"}, {"rolled-back", "rolled back"}, {"pending", "PENDING"}, {"unknown", "unknown"},
		{"failed", "failed"}, {"unsupported", "unsupported"}, {"interrupted", "interrupted"}, {"skipped", "skipped"},
		{"not-started", "not started"},
	} {
		if n := m[w.key]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, w.text))
		}
	}
	if len(parts) == 0 {
		return "0 devices"
	}
	return strings.Join(parts, ", ")
}

// finish prints the summary and the notes and returns the exit status
// (D130): 0 every device applied, checked or had no change, 1 a device
// failed, rolled back or is pending (or the review was not answered), 2 with
// --exit-code a check that found a change, 130 interrupted.
func (c *applyCtl) finish(sum batch.Summary, declined bool) error {
	inv, aa := c.inv, c.aa
	m := c.tally()
	bad := m["failed"] + m["unsupported"] + m["rolled-back"] + m["pending"] + m["unknown"] + m["applied-by-other"] + m["interrupted"]
	code := batch.ExitOK
	switch {
	case sum.Interrupted:
		code = batch.ExitInterrupted
	case bad > 0, declined:
		code = batch.ExitFailed
	case aa.exitCode && m["checked"] > 0:
		code = batch.ExitDiffers
	}
	if aa.pull.json {
		s := map[string]any{"checked": m["checked"], "no_change": m["no-change"], "applied": m["applied"] + m["applied-by-other"],
			"rolled_back": m["rolled-back"], "pending": m["pending"] + m["unknown"], "failed": m["failed"] + m["unsupported"],
			"skipped": m["skipped"], "not_started": m["not-started"], "exit": code}
		switch {
		case sum.Interrupted:
			s["stop"] = "interrupted"
		case sum.Stop == batch.StopMaxFailures:
			s["stop"] = "max-failures"
		case sum.Stop == batch.StopAuthFailure:
			s["stop"] = "auth-failed"
		}
		if declined {
			s["stop"] = "not-approved"
		}
		if c.chosen != nil && c.chosen.skipped.any() {
			s["left_out"] = c.chosen.skipped.jsonMap()
		}
		b, _ := json.Marshal(map[string]any{"summary": s})
		inv.write(string(b) + "\n")
	} else {
		inv.echo("")
		inv.echo("  " + summaryLine(m))
		if l := sum.StopLine(); l != "" {
			inv.echo("  " + l)
		}
		// a rolled-back or failed device says what to do next when it has a hint
		for _, o := range c.rows {
			if o.Hint != "" && o.Status == "" && o.Out == nil {
				inv.echo("  " + o.Name + ": " + o.Hint)
			}
		}
		c.chosen.printSkipped(inv)
		if aa.check && m["checked"] > 0 {
			inv.echo("  Nothing was committed: --check ends after the device's own commit check.")
		}
	}
	// a device that may be running the change under its timer is said on
	// standard error, in red, whatever the output's format (D138)
	for _, o := range c.rows {
		if o.Out != nil && (o.Out.Exit == devapply.ExitPending || o.Out.Exit == devapply.ExitWindowShort || o.Out.Exit == devapply.ExitUnknown) {
			inv.stderrLine(ui.Red + "PENDING " + o.Name + ui.NC + ": do not type commit or commit check on the device before " +
				o.Out.Until.Format("15:04:05") + "; it rolls the change back by itself then unless someone commits.")
		}
	}
	if !aa.pull.json {
		inv.echo("")
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}
