package cli

// The device selection of 'device config pull' and 'diff' (D66, D67, D69):
// names, --all, --scope, --vendor and --stale, limited to what the caller
// may read and what the device login can reach.

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
}

// parseSelection reads the selectors of a pull or a diff. One of names,
// --all, --scope, --vendor or --stale is required; names stand alone; the
// filters combine.
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
	s.all, s.stale = p.Has("--all"), p.Has("--stale")
	s.scope, s.vendor = p.Value("--scope"), p.Value("--vendor")
	filters := s.stale || p.Has("--scope") || p.Has("--vendor")
	switch {
	case len(s.names) > 0 && (s.all || filters):
		return s, inv.argErr("Name the devices, or select them with --all, --scope, --vendor or --stale, not both.", usage)
	case s.all && filters:
		return s, inv.argErr("--all is every device; drop it to select with --scope, --vendor or --stale.", usage)
	case len(s.names) == 0 && !s.all && !filters:
		return s, inv.argErr("Name the devices to "+verb+", or select them with --all, --scope <name>, --vendor <vendor> or --stale.", usage)
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
	noScope, other, wti, notYours []string
}

func (s skippedDevices) any() bool {
	return len(s.noScope)+len(s.other)+len(s.wti)+len(s.notYours) > 0
}

// lines are the notes about what was left out, with the names.
func (s skippedDevices) lines() []string {
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
	add(s.wti, "WTI units are not read in this release (name one to see it recorded as unsupported)")
	add(s.notYours, "in a scope you are not a member of: the device login is your own account")
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
func (c *chosenDevices) printSkipped(inv *invocation) {
	for _, l := range c.skipped.lines() {
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

func (s skippedDevices) jsonMap() map[string][]string {
	m := map[string][]string{}
	for k, v := range map[string][]string{"no_scope": s.noScope, "vendor_other": s.other, "wti": s.wti, "not_your_scope": s.notYours} {
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
	out := &chosenDevices{render: inv.newManagedRender(ro, inv.callerScopes().restricted)}
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
				inv.app.Logger(inv.ctx, "auth.warning", "device config "+verb+" DENY user="+user+" device="+e.Name+" scope="+dash(e.Scope)+" reason=scope")
				return nil, inv.usageErr(msg + " (device " + e.Name + ")")
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
		switch {
		case !slices.Contains(sortedVendors(), e.Vendor):
			out.skipped.other = append(out.skipped.other, e.Name)
		case !e.Configured:
			out.skipped.noScope = append(out.skipped.noScope, e.Name)
		case e.Vendor == "wti" && sel.vendor != "wti":
			out.skipped.wti = append(out.skipped.wti, e.Name)
		case login && loginProblem(m, user, e.Scope) != "":
			out.skipped.notYours = append(out.skipped.notYours, e.Name)
		default:
			out.entries = append(out.entries, e)
		}
	}
	out.render.prepare(out.entries)
	if sel.stale {
		store := inv.configStore()
		recs, _ := store.Load()
		var keep []devreg.Entry
		for _, e := range out.entries {
			if e.Vendor == "wti" {
				continue
			}
			st, err := inv.staleness(store, recs, out.render, e)
			if err != nil || st.IsStale() {
				keep = append(keep, e)
			}
		}
		out.entries = keep
	}
	return out, nil
}

// staleness is the state of a device's configuration against today's
// rendering (D66): never, failed, differs or ok.
func (inv *invocation) staleness(store devconf.Store, recs *devconf.Records, render *managedRender, e devreg.Entry) (devconf.Staleness, error) {
	rec, _ := recs.Of(e.Name)
	switch {
	case rec == nil || rec.Result == "":
		return devconf.StaleNever, nil
	case rec.Result == devconf.ResultUnsupported && rec.Vendor == "wti":
		return devconf.StaleOK, nil
	case rec.Result != devconf.ResultOK:
		return devconf.StaleFailed, nil
	}
	stored := render.stored(store, e)
	if stored == nil {
		// No last good pull to compare (its file cannot be read): never.
		return devconf.StaleNever, nil
	}
	expected, err := render.Expected(e)
	if err != nil {
		// What would be rendered is unknown: the recorded states say it.
		return devconf.Recorded(rec), nil
	}
	return devconf.Stale(rec, stored, expected)
}

// refuseNetconfForCisco is the argument-time refusal of --transport netconf
// when every device that would be dialled is a Cisco device: none is read
// over NETCONF (D61), so nothing would be tried and no password asked for.
// A mixed selection fails the Cisco devices one by one, before any login of
// theirs, and reads the rest.
func (inv *invocation) refuseNetconfForCisco(entries []devreg.Entry, transport string) error {
	if transport != transportNetconf {
		return nil
	}
	dialled, cisco := 0, 0
	for _, e := range entries {
		if e.Vendor == "wti" {
			continue
		}
		dialled++
		if e.Vendor == "cisco" {
			cisco++
		}
	}
	if dialled > 0 && cisco == dialled {
		return inv.argErr(errNetconfNotRead.Error()+". Nothing was tried.", "Usage: tacctl device config "+deviceConfigUse("pull"))
	}
	return nil
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
