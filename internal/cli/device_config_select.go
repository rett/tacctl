package cli

// The device selection of 'device config pull', 'diff', 'plan' and 'apply'
// (D66, D67, D69, D267): names, --all, --scope, --vendor, --stale, --differs,
// --name and --ip, limited to what the caller may read and what the device
// login can reach.

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/ui"
)

// atoiIn is s as an integer within [lo, hi].
func atoiIn(s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n < lo || n > hi {
		return 0, strconv.ErrRange
	}
	return n, nil
}

// selection is what the command line asked for.
type selection struct {
	names         []string
	all, stale    bool
	scope, vendor string
	// differs keeps the devices whose last good pull differs from today's
	// rendering. nameFilter and addrFilter are the lower-cased items of
	// --name (a text the device's name contains) and --ip (an address, a
	// CIDR or a text the address contains), any of which matches (D267).
	differs                bool
	nameFilter, addrFilter []string
}

// anyFilter says whether a filter was given: the selectors that combine.
func (s selection) anyFilter() bool {
	return s.stale || s.differs || s.scope != "" || s.vendor != "" || len(s.nameFilter) > 0 || len(s.addrFilter) > 0
}

// matchesText says whether e passes --name and --ip: the helpers of
// 'device list', so a device is picked by the same words in both.
func (s selection) matchesText(e devreg.Entry) bool {
	return textFiltersMatch(e, s.nameFilter, s.addrFilter)
}

// textFiltersMatch is the --name and --ip test shared by the selection and
// 'device config list': an empty list passes everything, otherwise any item
// of it must match.
func textFiltersMatch(e devreg.Entry, names, addrs []string) bool {
	if len(names) > 0 && !anyContains(e.Name, names) {
		return false
	}
	if len(addrs) > 0 && !slices.ContainsFunc(addrs, func(a string) bool { return addrMatches(e.Address, a) }) {
		return false
	}
	return true
}

// textFilters reads --name and --ip. A flag given with no text (an empty
// value or only commas) selects nothing sensible, so it is refused.
func (inv *invocation) textFilters(p Parsed, usage string) (names, addrs []string, err error) {
	names, addrs = splitList(p.Values("--name")), splitList(p.Values("--ip"))
	for _, f := range []struct {
		flag string
		got  []string
	}{{"--name", names}, {"--ip", addrs}} {
		if p.Has(f.flag) && len(f.got) == 0 {
			return nil, nil, inv.argErr(f.flag+" takes a text, or a comma-separated list of them.", usage)
		}
	}
	return names, addrs, nil
}

// parseSelection reads the selectors of a pull, diff, plan or apply. One of
// names, --all, --scope, --vendor, --stale, --differs, --name or --ip is
// required; names and --all stand alone; the filters combine.
func (inv *invocation) parseSelection(p Parsed, verb string) (selection, error) {
	usage := "Usage: tacctl device config " + deviceConfigUse(verb)
	var s selection
	seen := map[string]bool{}
	for _, a := range p.Args {
		for _, n := range strings.Split(a, ",") {
			n = strings.TrimSpace(n)
			if n != "" && !seen[strings.ToLower(n)] {
				seen[strings.ToLower(n)] = true
				s.names = append(s.names, n)
			}
		}
	}
	s.all, s.stale, s.differs = p.Has("--all"), p.Has("--stale"), p.Has("--differs")
	s.scope, s.vendor = p.Value("--scope"), p.Value("--vendor")
	if p.Has("--scope") && s.scope == "" {
		return s, inv.argErr("--scope takes a scope name.", usage)
	}
	var err error
	if s.nameFilter, s.addrFilter, err = inv.textFilters(p, usage); err != nil {
		return s, err
	}
	filters := s.anyFilter() || p.Has("--scope") || p.Has("--vendor")
	switch {
	case len(s.names) > 0 && (s.all || filters):
		return s, inv.argErr("Name the devices, or select them with --all, --scope, --vendor, --stale, --differs, --name or --ip, not both.", usage)
	case s.all && filters:
		return s, inv.argErr("--all is every device; drop it to select with --scope, --vendor, --stale, --differs, --name or --ip.", usage)
	case len(s.names) == 0 && !s.all && !filters:
		return s, inv.argErr("Name the devices to "+verb+", or select them with --all, --scope <name>, --vendor <vendor>, --stale, --differs, --name <text> or --ip <addr|cidr|text>.", usage)
	}
	if p.Has("--vendor") && !slices.Contains([]string{"cisco", "juniper", "wti"}, s.vendor) {
		return s, inv.argErr("--vendor takes cisco, juniper or wti: '"+s.vendor+"'", usage)
	}
	return s, nil
}

// configLogin is the account the device login is: the invoking user, never
// root, as 'tacctl ssh' (D69).
func (inv *invocation) configLogin(what string) (string, error) {
	user := inv.app.Env.Get("SUDO_USER")
	if user == "" || user == "root" {
		return "", inv.usageErr(what + " logs in to the devices as the user who invoked it; run it from your own account, not as root")
	}
	if err := inv.verifySudoUser(what); err != nil {
		return "", err
	}
	return user, nil
}

// skippedDevices counts what a selection left out, by reason.
type skippedDevices struct {
	noScope, other, notYours []string
	// notJunos are the devices of a selector that 'device config apply'
	// leaves out: it writes to Junos devices only (0.2.9).
	notJunos []string
	// held are the devices a break-glass hold stands on: the server does
	// not answer them, so no login of the caller is accepted there (D126).
	held []string
	// afterPull are the devices 'device config apply --pull' read and then
	// left out: their fresh record is not one --stale or --differs keeps
	// (0.2.17 D268).
	afterPull []string
	// notCompared are the devices 'apply --pull' read and could not compare
	// with what tacctl renders: --differs leaves them out, and they are not
	// applied.
	notCompared []string
}

func (s skippedDevices) any() bool {
	return len(s.noScope)+len(s.other)+len(s.notYours)+len(s.held)+len(s.notJunos)+len(s.afterPull)+len(s.notCompared) > 0
}

// linesFor are the notes about what was left out, with the names.
func (s skippedDevices) linesFor(string) []string {
	var out []string
	add := func(names []string, why string) {
		if len(names) == 0 {
			return
		}
		shown := names
		more := ""
		if len(shown) > 5 {
			shown, more = shown[:5], " and "+strconv.Itoa(len(names)-5)+" more"
		}
		out = append(out, "skipped "+strconv.Itoa(len(names))+" ("+strings.Join(shown, ", ")+more+"): "+why)
	}
	add(s.noScope, "no scope's prefixes cover the address")
	add(s.other, "the vendor is 'other'; set it with: tacctl device vendor <name> cisco|juniper|wti")
	add(s.notYours, "in a scope you are not a member of: the device login is your own account")
	add(s.notJunos, "apply writes to Junos devices only in this release")
	add(s.afterPull, "pulled, and the fresh pull matches what tacctl renders (not --stale or --differs)")
	add(s.notCompared, "pulled, and could not be compared with what tacctl renders after the pull (not applied; see: tacctl device config diff <name>)")
	for _, n := range s.held {
		out = append(out, "skipped "+n+": "+holdRefusal(n))
	}
	return out
}

// chosenDevices is a resolved selection: the devices to read, in the
// registry's order, and how to render what each is expected to run.
type chosenDevices struct {
	entries []devreg.Entry
	render  *managedRender
	skipped skippedDevices
}

// printSkipped says what the selection left out.
func (c *chosenDevices) printSkipped(inv *invocation) { c.printSkippedFor(inv, "pull") }

// printSkippedFor is printSkipped in the words of a verb.
func (c *chosenDevices) printSkippedFor(inv *invocation, verb string) {
	for _, l := range c.skipped.linesFor(verb) {
		inv.echo("  " + l)
	}
}

// nothingSelected is the end of a run that selected no device: an info line
// (an empty array for a diff, a summary line for a pull, with --json), exit
// 0.
func (inv *invocation) nothingSelected(c *chosenDevices, asJSON, diff bool) error {
	if asJSON {
		if diff {
			return inv.printJSON([]diffDeviceJSON{})
		}
		sum := map[string]any{"ok": 0, "differ": 0, "failed": 0, "not_started": 0, "pool": 0, "exit": 0}
		if c.skipped.any() {
			sum["skipped"] = c.skipped.jsonMap()
		}
		b, err := json.Marshal(map[string]any{"summary": sum})
		if err != nil {
			return err
		}
		inv.write(string(b) + "\n")
		return nil
	}
	inv.app.Out.Info("No devices to read.")
	c.printSkipped(inv)
	return nil
}

// holdRefusal is why a device on which break-glass is held is not logged in
// to: the one line of D126.
func holdRefusal(name string) string {
	return "break-glass is held on " + name + ": the device does not authenticate your login until it is released (tacctl breakglass release " + name + ")"
}

func (s skippedDevices) jsonMap() map[string][]string {
	m := map[string][]string{}
	for k, v := range map[string][]string{"no_scope": s.noScope, "vendor_other": s.other, "not_your_scope": s.notYours, "break_glass_held": s.held, "not_junos": s.notJunos,
		"match_after_pull": s.afterPull, "not_compared_after_pull": s.notCompared} {
		if len(v) > 0 {
			m[k] = v
		}
	}
	return m
}

// loginAdmitted is nil when user may log in to a device of scope: an
// active tacctl user whose scopes hold it (as 'tacctl ssh').
func loginProblem(m *model.Model, user, scope string) string {
	u := m.User(user)
	switch {
	case u == nil:
		return "'" + user + "' is not a tacctl user; the devices are logged in to with your tacctl account, so only tacctl users may read them."
	case u.IsDisabled():
		return "tacctl user '" + user + "' is disabled; reading devices is for active tacctl users."
	case scope != "" && !slices.Contains(u.Scopes, scope):
		return "'" + user + "' has no access to scope '" + scope + "'"
	}
	return ""
}

// chooseDevices resolves a selection for user into the devices a verb
// reads. A device named but unusable (not found, an enrolled host, vendor
// other, in no scope, a scope the user is not in) is the verb's refusal;
// one a selector would pick is left out and counted.
func (inv *invocation) chooseDevices(sel selection, user string, login bool, verb string, ro managedOptions) (*chosenDevices, error) {
	_, res, err := inv.deviceLoad()
	if err != nil {
		return nil, err
	}
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	if msg := loginProblem(m, user, ""); login && msg != "" {
		return nil, inv.usageErr(msg)
	}
	out := &chosenDevices{render: inv.newManagedRender(ro, true)}
	visible := res.Visible(inv.deviceFilter())

	if len(sel.names) > 0 {
		for _, n := range sel.names {
			e, err := inv.deviceFind(res, n)
			if err != nil {
				return nil, err
			}
			switch {
			case e.Source == devreg.SourceHost:
				return nil, inv.usageErr("'" + e.Name + "' is an enrolled Linux host; the device verbs do not read it. See: tacctl host show " + e.Name)
			case !slices.Contains(sortedVendors(), e.Vendor):
				return nil, inv.usageErr("Device '"+e.Name+"' has vendor '"+e.Vendor+"', and only cisco, juniper and wti are read.",
					"Set the vendor with: tacctl device vendor "+e.Name+" cisco|juniper|wti")
			case !e.Configured:
				return nil, inv.usageErr("Device '"+e.Name+"' ("+dashAddrText(e.Address)+") is in no scope: no scope's prefixes cover its address.",
					"Add them with: tacctl scope prefixes <scope> add <cidr>")
			}
			if msg := loginProblem(m, user, e.Scope); login && msg != "" {
				inv.app.Audit().Raw("auth.warning", "device config "+verb+" DENY user="+user+" device="+e.Name+" scope="+dash(e.Scope)+" reason=scope")
				return nil, inv.usageErr(msg + " (device " + e.Name + ")")
			}
			// A held device does not accept the login; refused before any
			// device is dialled, as a batch would stop on an authentication
			// failure.
			if _, held := inv.holdOf(e.Name, e.Address); login && held {
				return nil, inv.usageErr(holdRefusal(e.Name))
			}
			out.entries = append(out.entries, e)
		}
		out.render.prepare(out.entries)
		return out, nil
	}

	if sel.scope != "" {
		if err := inv.scopeRequire(sel.scope); err != nil {
			return nil, err
		}
		if err := inv.scopeNotFound(inv.callerScopes(), sel.scope); err != nil {
			return nil, err
		}
	}
	for _, e := range visible {
		if e.Source != devreg.SourceDevice {
			continue
		}
		if sel.scope != "" && e.Scope != sel.scope {
			continue
		}
		if sel.vendor != "" && e.Vendor != sel.vendor {
			continue
		}
		if !sel.matchesText(e) {
			continue
		}
		switch {
		case !slices.Contains(sortedVendors(), e.Vendor):
			out.skipped.other = append(out.skipped.other, e.Name)
		case !e.Configured:
			out.skipped.noScope = append(out.skipped.noScope, e.Name)
		case login && loginProblem(m, user, e.Scope) != "":
			out.skipped.notYours = append(out.skipped.notYours, e.Name)
		case login && inv.isHeld(e.Name, e.Address):
			out.skipped.held = append(out.skipped.held, e.Name)
		default:
			out.entries = append(out.entries, e)
		}
	}
	out.render.prepare(out.entries)
	inv.applyStaleFilters(sel, out)
	return out, nil
}

// applyStaleFilters keeps, of c.entries, the devices --stale and --differs
// select, from the records and today's rendering: no login is made (D267).
// --stale is never, failed, differs and pull (a record that cannot be
// compared is kept); --differs is the state differs alone. Both together
// are both tests. It is a step of its own so that a run that pulls first
// can apply it to the fresh records.
func (inv *invocation) applyStaleFilters(sel selection, c *chosenDevices) {
	if !sel.stale && !sel.differs {
		return
	}
	store := inv.configStore()
	recs, _ := store.Load()
	var keep []devreg.Entry
	for _, e := range c.entries {
		st, err := inv.staleness(store, recs, c.render, e)
		if sel.stale && err == nil && !st.IsStale() {
			continue
		}
		if sel.differs && (err != nil || st != devconf.StaleDiffers) {
			continue
		}
		keep = append(keep, e)
	}
	c.entries = keep
}

// staleness is the state of a device's configuration against today's
// rendering (D66): never, failed, differs or ok; pull for a syntax nothing
// says (D113) and for a vendor changed since the pull (D260).
func (inv *invocation) staleness(store devconf.Store, recs *devconf.Records, render *managedRender, e devreg.Entry) (devconf.Staleness, error) {
	rec, _ := recs.Of(e.Name)
	switch {
	case rec == nil || rec.Result == "":
		return devconf.StaleNever, nil
	case rec.Result != devconf.ResultOK:
		return devconf.StaleFailed, nil
	case devconf.VendorChanged(rec, e.Vendor):
		// The stored sections are of the old vendor's shape (D260).
		return devconf.StalePull, nil
	}
	stored := render.stored(store, e)
	if stored == nil {
		// No last good pull to compare (its file cannot be read): never.
		return devconf.StaleNever, nil
	}
	// A Cisco device whose syntax nothing says (D113: the setting is auto
	// and the record has none, as every record of 0.2.4) is compared
	// neither as IOS 12.x nor as the modern syntax: one pull makes it known.
	if inv.syntaxMatters(e) && devconf.NeedsSyntax(rec, e.ConfigSyntax) {
		return devconf.StalePull, nil
	}
	expected, err := render.Expected(e)
	if err != nil {
		// What would be rendered is unknown: the recorded states say it.
		return devconf.Recorded(rec), nil
	}
	return devconf.Stale(rec, stored, expected)
}

// refuseNetconfForCisco is the argument-time refusal of --transport netconf
// when every device that would be dialled is one that is not read over NETCONF
// (a Cisco device, D61, or a WTI unit, which has none): nothing would be
// tried and no password asked for. A mixed selection fails those devices one
// by one, before any login of theirs, and reads the rest.
func (inv *invocation) refuseNetconfForCisco(entries []devreg.Entry, transport string) error {
	if transport != transportNetconf || len(entries) == 0 {
		return nil
	}
	cisco, unit := 0, 0
	for _, e := range entries {
		switch e.Vendor {
		case "cisco":
			cisco++
		case "wti":
			unit++
		}
	}
	var why error
	switch {
	case cisco+unit != len(entries):
		return nil
	case unit == 0:
		why = errNetconfNotRead
	case cisco == 0:
		why = errNetconfNotReadWTI
	default:
		why = errNetconfNotReadMixed
	}
	return inv.argErr(why.Error()+". Nothing was tried.", "Usage: tacctl device config "+deviceConfigUse("pull"))
}

// stored are the managed sections of a device's last good pull. A file that
// cannot be read is no last good pull (nil; the next pull writes it again),
// and it is said once per device in a run, on stderr, so a JSON output stays
// clean.
func (r *managedRender) stored(store devconf.Store, e devreg.Entry) map[string]devices.Section {
	secs, err := store.Sections(e.Name, e.Vendor)
	if err == nil {
		return secs
	}
	key := "stored " + strings.ToLower(e.Name)
	if !r.logged[key] {
		r.logged[key] = true
		ui.Output{Stdout: r.inv.app.Out.Stderr}.Warn("The stored sections of '" + e.Name + "' cannot be read; 'tacctl device config pull " +
			e.Name + "' makes them again.")
	}
	return nil
}
