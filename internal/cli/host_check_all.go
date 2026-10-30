package cli

// 'host check <name>... | --all [--json]' (0.2.15 plan D216-D218): what
// 'host show <name> --check' does for each of several hosts, with nothing
// written here and nothing changed on any host. A held host is skipped, not
// refused: a check is read-only, so there is nothing to refuse the person.
// It logs in as the invoker and has no tier row, so the gate leaves it to the
// superuser.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

// hostCheckUsage is the usage line of 'host check'.
const hostCheckUsage = "Usage: tacctl host check <name>... | --all [--json] [--concurrency <n>]"

// The states of one host in 'host check' (the "state" of --json).
const (
	checkOK          = "ok"
	checkDifferences = "differences"
	checkFailed      = "failed"
	checkHeld        = "held"
)

// hostCheckAllJSON is one host of 'host check --json'.
type hostCheckAllJSON struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	// State is checkOK, checkDifferences, checkFailed or checkHeld.
	State       string         `json:"state"`
	Differences []hostDiffJSON `json:"differences"`
	Notes       []string       `json:"notes"`
	// Error is why the host could not be checked (checkFailed), else "".
	Error      string          `json:"error"`
	Breakglass *deviceHoldJSON `json:"breakglass,omitempty"`
}

// hostCheckAll is 'host check'.
func (inv *invocation) hostCheckAll(args []string) error {
	a := inv.app
	p, err := Parse(hostSpecs["check"], args)
	if err != nil {
		msg := err.Error()
		if uf, ok := err.(*UnknownFlagError); ok {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, hostCheckUsage)
	}
	all, asJSON := p.Has("--all"), p.Has("--json")
	concurrency := 1
	if p.Has("--concurrency") {
		if concurrency, err = inv.hostConcurrency(p.Value("--concurrency"), hostCheckUsage); err != nil {
			return err
		}
	}
	var typed []string
	for _, n := range p.Args {
		if !slices.Contains(typed, n) {
			typed = append(typed, n)
		}
	}
	if !all && len(typed) == 0 {
		return inv.usageErr(hostCheckUsage)
	}
	if all && len(typed) > 0 {
		return inv.usageErr("Give names or --all, not both.")
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	names := typed
	if all {
		names = nil
		if reg.Exists() {
			names = reg.Names()
		}
	}
	// Every name is checked before the first host is touched (D214).
	var entries []hosts.Entry
	for _, name := range names {
		e, ok := reg.Find(name)
		if !ok || e.Line == "" {
			return inv.usageErr("No enrolled host named '" + name + "'. See 'tacctl host list'.")
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		if asJSON {
			return inv.printJSON([]hostCheckAllJSON{})
		}
		a.Out.Info("No hosts enrolled.")
		return nil
	}
	f, lerr := inv.hostDevices()
	if lerr != nil {
		// A host that is not this server needs the device registry to tell
		// whether it is held; none is touched before that is known.
		for _, e := range entries {
			if e.Target != hosts.Local {
				return inv.hostHoldUnreadable(e, lerr)
			}
		}
	}

	results := make([]hostCheckAllJSON, len(entries))
	if pool := min(concurrency, len(entries)); pool > 1 {
		names, keys := make([]string, len(entries)), make([]string, len(entries))
		for i, e := range entries {
			names[i], keys[i] = e.Name, hostTargetKey(e)
		}
		run := inv.runHostPool(names, keys, pool, func(st *hostStep, i int) (bool, error) {
			r, err := inv.hostCheckOne(st, f, entries[i], asJSON)
			results[i] = r
			return false, err
		})
		if run.sum.Interrupted {
			return ui.ErrInterrupted
		}
		if err := firstError(run.errs); err != nil {
			return err
		}
		// a host whose job panicked is one that could not be checked
		for i, text := range run.panics {
			if text == "" {
				continue
			}
			r := hostCheckAllJSON{Name: entries[i].Name, Target: entries[i].Target, State: checkFailed,
				Error: "stopped by an internal error: " + text, Differences: []hostDiffJSON{}, Notes: []string{}}
			results[i] = r
		}
	} else {
		st := inv.sequentialStep()
		for i, e := range entries {
			r, err := inv.hostCheckOne(st, f, e, asJSON)
			if err != nil {
				return err
			}
			results[i] = r
		}
	}

	if asJSON {
		if err := inv.printJSON(results); err != nil {
			return err
		}
	} else if len(results) > 1 {
		inv.echo(hostCheckSummary(results))
	}
	for _, r := range results {
		if r.State == checkDifferences || r.State == checkFailed {
			return exit(1)
		}
	}
	return nil
}

// hostCheckOne is the check of one host of 'host check': its result, with
// the text report of the host already printed (st.serial: in the host's own
// output when hosts run side by side). err ends the command.
func (inv *invocation) hostCheckOne(st *hostStep, f *devreg.File, e hosts.Entry, asJSON bool) (hostCheckAllJSON, error) {
	r := hostCheckAllJSON{Name: e.Name, Target: e.Target, Differences: []hostDiffJSON{}, Notes: []string{}}
	var v *hostShowJSON
	var he *hosts.Env
	var err error
	held := false
	st.serial(func() {
		if h, isHeld := inv.hostHoldIn(f, e); isHeld {
			held = true
			r.State = checkHeld
			r.Breakglass = holdJSONOfHold(h)
			if !asJSON {
				inv.echo(e.Name + ": skipped: break-glass is held on it " + inv.holdSummary(h) + ": " + h.Reason + " (tacctl breakglass release " + e.Name + ")")
			}
			return
		}
		if v, err = inv.hostView(e); err != nil {
			return
		}
		// What the host prints besides the check goes to stderr, so
		// standard output holds the results alone.
		he = inv.hostCheckEnv(st, true)
	})
	if held || err != nil {
		return r, err
	}
	c, failed, err := inv.hostCheckRun(st.ctx, he, e, v)
	if err != nil {
		return r, err
	}
	switch {
	case failed != "":
		r.State, r.Error = checkFailed, failed
	case len(c.Differences) > 0:
		r.State, r.Differences, r.Notes = checkDifferences, c.Differences, c.Notes
	default:
		r.State, r.Notes = checkOK, c.Notes
	}
	if !asJSON {
		st.serial(func() { inv.hostCheckAllText(r) })
	}
	return r, nil
}

// hostCheckAllText prints one host of the text report (a held host's line is
// printed where it is found).
func (inv *invocation) hostCheckAllText(r hostCheckAllJSON) {
	switch r.State {
	case checkOK:
		inv.echo(r.Name + ": as tacctl would make it.")
	case checkDifferences:
		inv.echo(r.Name + ": " + howMany(len(r.Differences), "difference") + ":")
		for _, d := range r.Differences {
			inv.echo("  - " + d.Text + ". Fix: " + d.Fix)
		}
	case checkFailed:
		inv.echo(r.Name + ": could not be checked: " + r.Error)
	}
	for _, n := range r.Notes {
		inv.echo("  " + n)
	}
}

// hostCheckSummary is the line that ends a report of several hosts: how
// many are in each state, the empty ones left out.
func hostCheckSummary(rs []hostCheckAllJSON) string {
	n := map[string]int{}
	for _, r := range rs {
		n[r.State]++
	}
	var parts []string
	for _, s := range []struct{ state, text string }{
		{checkOK, "as tacctl would make it"}, {checkDifferences, "with differences"},
		{checkFailed, "not checked"}, {checkHeld, "skipped (held)"}} {
		if n[s.state] > 0 {
			parts = append(parts, strconv.Itoa(n[s.state])+" "+s.text)
		}
	}
	return howMany(len(rs), "host") + ": " + strings.Join(parts, ", ") + "."
}
