package cli

// 'device config list' and 'device config forget' (D65, D66), and the
// configuration state the 'CONFIG' column of 'device list' and the block of
// 'device show' print from the same records.

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// configState is the CONFIG column's word for an entry from its record
// alone (no rendering): ok, differs, never, failed; "-" for a host, a
// vendor that is not read (other) and a device no scope covers (a pull
// refuses it, so it is neither never nor stale).
func configState(e devreg.Entry, rec *devconf.Record) string {
	switch {
	case e.Source == devreg.SourceHost, e.Vendor == "other":
		return "-"
	case !e.Configured:
		return "-"
	}
	return string(devconf.Recorded(rec))
}

// configStateOf is configState with D113's state laid over it: a Cisco
// device of a TACACS+ scope whose syntax is unknown says 'pull'.
func (inv *invocation) configStateOf(e devreg.Entry, rec *devconf.Record) string {
	st := configState(e, rec)
	if st == string(devconf.StaleOK) || st == string(devconf.StaleDiffers) {
		if inv.syntaxMatters(e) {
			return string(devconf.WithSyntax(devconf.Staleness(st), rec, e.ConfigSyntax, true))
		}
	}
	return st
}

// configVisible says whether the caller is shown the configuration state of
// the devices (the CONFIG column, the Configuration row, the config field of
// the JSON): the operator tier and up, as 'device config list' is (D69).
// The read-only tier's output has none of it, not an empty column.
func (inv *invocation) configVisible() bool {
	t := inv.tierGate().Caller(inv.ctx)
	return t == tier.Unrestricted || t == tier.Superuser || tier.Rank(t) >= tier.Rank(tier.Operator)
}

// configLoad reads the records, for the display verbs: a file that cannot be
// read is none (the next pull rebuilds it).
func (inv *invocation) configRecords() *devconf.Records {
	recs, _ := inv.configStore().Load()
	return recs
}

// appliedCell is the APPLIED column of 'device config list' (D138): what
// 'device config apply' last did to the device, "-" for nothing.
func appliedCell(a *devconf.Applied) string {
	switch {
	case a == nil || a.Result == "":
		return "-"
	case a.Result == devconf.AppliedPending && !a.Until.IsZero():
		return "PENDING " + a.Until.Format("15:04")
	case a.Result == devconf.AppliedPending:
		return "PENDING"
	case a.Result == devconf.AppliedApplied:
		return "applied " + seenTime(a.At)
	}
	return a.Result
}

// applyBlock is the apply half of the Configuration row: when, by whom, the
// change identifier and the shape of the last check or apply, and for a
// pending commit what must not be typed.
func applyBlock(a *devconf.Applied) string {
	if a == nil || a.Result == "" {
		return ""
	}
	who := ""
	if a.By != "" {
		who = " by " + a.By
	}
	detail := func(parts ...string) string {
		var kept []string
		for _, p := range parts {
			if p != "" {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 {
			return ""
		}
		return " (" + strings.Join(kept, ", ") + ")"
	}
	shape := ""
	if a.Shape != "" {
		shape = "shape " + a.Shape
	}
	when := ""
	if !a.At.IsZero() {
		when = " " + seenTime(a.At)
	}
	switch a.Result {
	case devconf.AppliedApplied:
		return "applied" + when + who + detail(a.ID, shape)
	case devconf.AppliedChecked:
		return "checked" + when + who + detail(shape)
	case devconf.AppliedPending, devconf.AppliedUnknown:
		until := ""
		if !a.Until.IsZero() {
			until = " until " + a.Until.Format("15:04:05")
		}
		word := "PENDING"
		if a.Result == devconf.AppliedUnknown {
			word = "unknown, may be pending"
		}
		return ui.Red + word + until + ui.NC + detail(a.ID) + ": do not type commit or commit check on the device"
	}
	// rolled-back, failed
	s := strings.ReplaceAll(a.Result, "-", " ") + when + who + detail(a.ID)
	if a.Reason != "" {
		s += ": " + cleanLine(a.Reason)
	}
	return s
}

// appliedJSON is the apply record in --json: no raw output, no secret.
type appliedJSON struct {
	Result   string   `json:"result"`
	Kind     string   `json:"kind,omitempty"`
	At       string   `json:"at,omitempty"`
	By       string   `json:"by,omitempty"`
	ID       string   `json:"id,omitempty"`
	Shape    string   `json:"shape,omitempty"`
	Sections []string `json:"sections,omitempty"`
	Set      int      `json:"set,omitempty"`
	Delete   int      `json:"delete,omitempty"`
	Insert   int      `json:"insert,omitempty"`
	Until    string   `json:"until,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Commit   int      `json:"commit,omitempty"`
}

// appliedJSONOf is the record's apply part for --json; nil when there is
// none.
func appliedJSONOf(a *devconf.Applied) *appliedJSON {
	if a == nil || a.Result == "" {
		return nil
	}
	j := &appliedJSON{Result: a.Result, Kind: a.Kind, By: a.By, ID: a.ID, Shape: a.Shape, Sections: a.Sections,
		Set: a.Set, Delete: a.Delete, Insert: a.Insert, Reason: cleanLine(a.Reason)}
	if !a.At.IsZero() {
		j.At = a.At.UTC().Format(time.RFC3339)
	}
	if !a.Until.IsZero() {
		j.Until = a.Until.UTC().Format(time.RFC3339)
	}
	if a.Commit != nil {
		j.Commit = a.Commit.Seq
	}
	return j
}

// configBlock is the 'Configuration' row of 'device show': when, by whom
// and over what the last pull read the device, its result and the state of
// each section, then what 'device config apply' last did to it.
func configBlock(e devreg.Entry, rec *devconf.Record) string {
	s := pullBlock(e, rec)
	if rec != nil {
		if a := applyBlock(rec.Applied); a != "" {
			s += "; apply: " + a
		}
	}
	return s
}

// pullBlock is the pull half of the Configuration row.
func pullBlock(e devreg.Entry, rec *devconf.Record) string {
	switch {
	case !e.Configured:
		return "not read (no scope's prefixes cover its address)"
	case rec == nil || rec.Result == "":
		return "never pulled (tacctl device config pull " + e.Name + ")"
	}
	var b strings.Builder
	if rec.Pulled.IsZero() {
		b.WriteString("never pulled")
	} else {
		b.WriteString("pulled " + seenTime(rec.Pulled))
		if rec.By != "" {
			b.WriteString(" by " + rec.By)
		}
		if rec.Transport != "" {
			b.WriteString(" over " + rec.Transport)
			if rec.Netconf != "" && rec.Netconf != netconfNotProbed {
				b.WriteString(" (" + rec.Netconf + ")")
			}
		}
	}
	b.WriteString(", " + rec.Result)
	if rec.Result != devconf.ResultOK {
		b.WriteString(" (the last attempt)")
	}
	if len(rec.Sections) > 0 {
		var parts []string
		for _, n := range devconf.SectionNames {
			if s, ok := rec.Sections[n]; ok {
				r := devconf.SectionResult{State: devconf.State(s.State), Unmanaged: s.Unmanaged}
				parts = append(parts, n+" "+r.StateText())
			}
		}
		b.WriteString("; sections: " + strings.Join(parts, ", "))
	}
	// A WTI unit: its command menu's version, its own Site ID and who else
	// was logged in at that pull (a count, no name).
	if e.Vendor == "wti" && rec.Result == devconf.ResultOK {
		var facts []string
		if rec.OS != "" {
			facts = append(facts, "command menu "+cleanLine(rec.OS))
		}
		if u := rec.Unit; u != nil {
			if u.SiteID != "" {
				facts = append(facts, "site ID "+cleanLine(u.SiteID))
			}
			if u.OtherSessions > 0 {
				facts = append(facts, sessionsText(u.OtherSessions))
			}
		}
		if len(facts) > 0 {
			b.WriteString("; " + strings.Join(facts, ", "))
		}
	}
	return b.String()
}

// listJSON is one device of 'device config list --json'.
type listJSON struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Vendor    string `json:"vendor"`
	State     string `json:"state"`
	Result    string `json:"result,omitempty"`
	Pulled    string `json:"pulled,omitempty"`
	By        string `json:"by,omitempty"`
	Transport string `json:"transport,omitempty"`
	Netconf   string `json:"netconf,omitempty"`
	// Release is the OS release the last good pull read from the device
	// (a WTI unit's command menu version); absent when none was read.
	Release  string            `json:"release,omitempty"`
	Sections map[string]string `json:"sections,omitempty"`
	// Applied is what 'device config apply' last did (absent: nothing).
	Applied   *appliedJSON `json:"applied,omitempty"`
	DiffersIn []string     `json:"differs_in,omitempty"`
	// Unmanaged counts, per section that is ok, the device's own
	// statements it holds beside what tacctl renders.
	Unmanaged map[string]int `json:"unmanaged,omitempty"`
	// SyntaxConflict is set when the device's explicit config-syntax is not
	// the syntax its last pull's version line derives to (the setting wins);
	// ImageSyntax is what the line says.
	SyntaxConflict bool   `json:"syntax_conflict,omitempty"`
	ImageSyntax    string `json:"image_syntax,omitempty"`
	// Unit is what the last good pull of a WTI unit saw beside its sections.
	Unit *listUnitJSON `json:"unit,omitempty"`
}

// listUnitJSON is a WTI unit's facts in 'device config list --json': the
// command menu's version (the record's os), the unit's Site ID and how many
// other sessions it had at that pull.
type listUnitJSON struct {
	Version       string `json:"version,omitempty"`
	SiteID        string `json:"site_id,omitempty"`
	OtherSessions int    `json:"other_sessions"`
	UsersRead     bool   `json:"users_read"`
}

// deviceConfigList is 'device config list'.
func (inv *invocation) deviceConfigList(args []string) error {
	p, err := inv.deviceConfigParse("list", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("list"); err != nil {
		return err
	}
	usage := "Usage: tacctl device config " + deviceConfigUse("list")
	if p.Has("--vendor") && !slices.Contains([]string{"cisco", "juniper", "wti"}, p.Value("--vendor")) {
		return inv.argErr("--vendor takes cisco, juniper or wti: '"+p.Value("--vendor")+"'", usage)
	}
	if p.Has("--transport") && !slices.Contains([]string{"netconf", "ssh", "none"}, p.Value("--transport")) {
		return inv.argErr("--transport takes netconf, ssh or none: '"+p.Value("--transport")+"'", usage)
	}
	if p.Has("--scope") {
		if err := inv.scopeRequire(p.Value("--scope")); err != nil {
			return err
		}
		if err := inv.scopeNotFound(inv.callerScopes(), p.Value("--scope")); err != nil {
			return err
		}
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	var entries []devreg.Entry
	for _, e := range res.Visible(inv.deviceFilter()) {
		if e.Source != devreg.SourceDevice || !slices.Contains(sortedVendors(), e.Vendor) {
			continue
		}
		if (p.Has("--scope") && e.Scope != p.Value("--scope")) || (p.Has("--vendor") && e.Vendor != p.Value("--vendor")) {
			continue
		}
		entries = append(entries, e)
	}
	// The states are computed against today's rendering (a change of the
	// store makes a device differ without a new pull); a device that cannot
	// be rendered for shows the state its record holds.
	render := inv.newManagedRender(managedOptions{}, false)
	render.prepare(entries)
	store := inv.configStore()
	recs, _ := store.Load()

	wantStale, wantNever, wantFailed, wantDiffers := p.Has("--stale"), p.Has("--never"), p.Has("--failed"), p.Has("--differs")
	filtered := wantStale || wantNever || wantFailed || wantDiffers
	type row struct {
		e      devreg.Entry
		rec    *devconf.Record
		state  string
		differ []string
		// own counts the device's own statements per section that is ok.
		own map[string]int
		// conflict is the syntax the version line derives to when the
		// explicit setting contradicts it ("" otherwise).
		conflict string
	}
	var rows []row
	for _, e := range entries {
		rec, _ := recs.Of(e.Name)
		state := inv.configStateOf(e, rec)
		var differ []string
		var own map[string]int
		if e.Configured {
			if st, err := inv.staleness(store, recs, render, e); err == nil {
				state = string(st)
			}
			if state == string(devconf.StaleDiffers) || state == string(devconf.StaleOK) {
				rs := inv.comparedNow(store, rec, render, e)
				differ = differingSections(rs)
				own = unmanagedSections(rs)
			}
		}
		if p.Has("--transport") {
			tr := ""
			if rec != nil {
				tr = rec.Transport
			}
			if want := p.Value("--transport"); (want == "none" && tr != "") || (want != "none" && tr != want) {
				continue
			}
		}
		if filtered {
			ok := (wantStale && state != string(devconf.StaleOK)) ||
				(wantNever && state == string(devconf.StaleNever)) ||
				(wantFailed && state == string(devconf.StaleFailed)) ||
				(wantDiffers && state == string(devconf.StaleDiffers))
			if !ok || !e.Configured {
				continue
			}
		}
		var conflict string
		if rec != nil && inv.syntaxMatters(e) {
			if sr := syntaxOf(e, rec); sr.Conflict {
				conflict = sr.ImageSyntax
			}
		}
		rows = append(rows, row{e, rec, state, differ, own, conflict})
	}
	if p.Has("--json") {
		out := []listJSON{}
		for _, r := range rows {
			j := listJSON{Name: r.e.Name, Scope: r.e.Scope, Vendor: r.e.Vendor, State: r.state, DiffersIn: r.differ, Unmanaged: r.own,
				SyntaxConflict: r.conflict != "", ImageSyntax: r.conflict}
			if u := r.rec; u != nil && r.e.Vendor == "wti" && u.Unit != nil && u.Result == devconf.ResultOK {
				j.Unit = &listUnitJSON{Version: cleanLine(u.OS), SiteID: cleanLine(u.Unit.SiteID),
					OtherSessions: u.Unit.OtherSessions, UsersRead: u.Unit.UsersRead}
			}
			if r.rec != nil {
				j.Result, j.By, j.Transport = r.rec.Result, r.rec.By, r.rec.Transport
				j.Release = cleanLine(r.rec.Release)
				j.Applied = appliedJSONOf(r.rec.Applied)
				if !r.rec.Pulled.IsZero() {
					j.Pulled = r.rec.Pulled.UTC().Format(time.RFC3339)
				}
				if r.rec.Netconf != netconfNotProbed {
					j.Netconf = r.rec.Netconf
				}
				if len(r.rec.Sections) > 0 {
					j.Sections = map[string]string{}
					for n, s := range r.rec.Sections {
						j.Sections[n] = s.State
					}
				}
			}
			out = append(out, j)
		}
		return inv.printJSON(out)
	}
	head := "Device configurations (" + strconv.Itoa(len(rows)) + ")"
	if len(rows) == 0 {
		inv.echo("")
		inv.echoE(ui.Bold + head + ui.NC)
		inv.echo(ui.Rule(head))
		if filtered {
			inv.echo("  None: every device read so far matches what tacctl renders.")
		} else {
			inv.echo("  None. Read one with: tacctl device config pull <name>")
		}
		inv.echo("")
		return nil
	}
	// The APPLIED column appears once a listed device has been checked or
	// applied (0.2.9): a list of devices that never were has the columns it
	// always had.
	withApplied := slices.ContainsFunc(rows, func(r row) bool { return r.rec != nil && appliedCell(r.rec.Applied) != "-" })
	cols := []ui.Col{ui.Left("NAME"), ui.Left("SCOPE"), ui.Left("VENDOR"), ui.Left("RELEASE"), ui.Left("CONFIG")}
	if withApplied {
		cols = append(cols, ui.Left("APPLIED"))
	}
	cols = append(cols, ui.Left("PULLED"), ui.Left("BY"), ui.Left("VIA"), ui.Left("NETCONF"), ui.Left("DETAIL"))
	tb := ui.NewTable(head, cols...)
	for _, r := range rows {
		pulled, by, via, nc, detail, release := "-", "-", "-", "-", "-", "-"
		if r.rec != nil {
			release = dash(cleanLine(r.rec.Release))
			if !r.rec.Pulled.IsZero() {
				pulled = seenTime(r.rec.Pulled)
			}
			by, via = dash(r.rec.By), dash(r.rec.Transport)
			if r.rec.Netconf != "" {
				nc = r.rec.Netconf
			}
			switch {
			case r.state == string(devconf.StaleFailed):
				detail = r.rec.Result
			case len(r.differ) > 0:
				detail = strings.Join(r.differ, ",")
			case len(r.own) > 0:
				// ok beside the device's own statements
				var parts []string
				for _, n := range devconf.SectionNames {
					if c := r.own[n]; c > 0 {
						parts = append(parts, n+" +"+strconv.Itoa(c)+" unmanaged")
					}
				}
				detail = strings.Join(parts, ", ")
			}
		}
		if r.state == string(devconf.StalePull) {
			detail = devconf.NeedsPullText
		}
		// A WTI unit: who else was logged in at the last good pull.
		if r.rec != nil && r.e.Vendor == "wti" && r.rec.Result == devconf.ResultOK && r.rec.Unit != nil && r.rec.Unit.OtherSessions > 0 {
			if detail == "-" {
				detail = sessionsText(r.rec.Unit.OtherSessions)
			} else {
				detail += "; " + sessionsText(r.rec.Unit.OtherSessions)
			}
		}
		if r.conflict != "" {
			// The setting wins; the pull's image says another syntax.
			note := "config-syntax " + r.e.ConfigSyntax + ", the pull read " + r.conflict
			if detail == "-" {
				detail = note
			} else {
				detail += "; " + note
			}
		}
		if !r.e.Configured {
			detail = "no scope"
		}
		cells := []any{r.e.Name, dash(r.e.Scope), r.e.Vendor, release, r.state}
		if withApplied {
			ap := "-"
			if r.rec != nil {
				ap = appliedCell(r.rec.Applied)
			}
			cells = append(cells, ap)
		}
		tb.Add(append(cells, pulled, by, via, nc, detail)...)
	}
	inv.write(tb.String())
	inv.echo("")
	return nil
}

// unmanagedSections counts, per section that is ok, the device's own
// statements it holds (nil when none has any).
func unmanagedSections(rs []devconf.SectionResult) map[string]int {
	var out map[string]int
	for _, r := range rs {
		if r.State == devconf.StateOK && r.Unmanaged > 0 {
			if out == nil {
				out = map[string]int{}
			}
			out[r.Name] = r.Unmanaged
		}
	}
	return out
}

// comparedNow is the comparison of a device's stored pull with today's
// rendering (nil when there is none to make).
func (inv *invocation) comparedNow(store devconf.Store, rec *devconf.Record, render *managedRender, e devreg.Entry) []devconf.SectionResult {
	if rec == nil {
		return nil
	}
	stored := render.stored(store, e)
	if len(stored) == 0 {
		return nil
	}
	expected, err := render.Expected(e)
	if err != nil {
		return nil
	}
	rs, err := devconf.CompareAll(expected, rec.Extracted(stored))
	if err != nil {
		return nil
	}
	return rs
}

// deviceConfigForget is 'device config forget': the records (and the
// stored sections) of the named devices, or of every device. They are
// derived data: a pull rebuilds them.
func (inv *invocation) deviceConfigForget(args []string) error {
	p, err := inv.deviceConfigParse("forget", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("forget"); err != nil {
		return err
	}
	usage := "Usage: tacctl device config " + deviceConfigUse("forget")
	var names []string
	for _, a := range p.Args {
		for _, n := range strings.Split(a, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	store := inv.configStore()
	switch {
	case p.Has("--all") && len(names) > 0:
		return inv.argErr("--all takes no name.", usage)
	case p.Has("--all"):
		n, err := store.ForgetAll()
		if err != nil {
			return err
		}
		inv.app.Out.Info("Forgot the configuration records of " + howMany(n, "device") + ".")
		inv.app.Logger(inv.ctx, "auth.info", "device config forget user="+inv.sudoUser()+" device=* count="+strconv.Itoa(n))
		return nil
	case len(names) == 0:
		return inv.argErr("Name the devices to forget, or give --all.", usage)
	}
	for _, n := range names {
		had, err := store.Forget(n)
		if err != nil {
			return err
		}
		if !had {
			inv.app.Out.Info("No configuration record for '" + n + "'.")
			continue
		}
		inv.app.Out.Info("Forgot the configuration record of '" + n + "'.")
		inv.app.Logger(inv.ctx, "auth.info", "device config forget user="+inv.sudoUser()+" device="+n)
	}
	return nil
}

// configCarry moves a renamed device's configuration record to its new name,
// or, with no new name, drops a removed device's (D65). It is best effort: a
// record is derived data, and a device with none costs no file.
func (inv *invocation) configCarry(oldName, newName string) {
	store := inv.configStore()
	if _, err := os.Stat(store.Records); err != nil {
		if p := filepath.Join(store.Dir, strings.ToLower(oldName)+".yaml"); !fileThere(p) {
			return
		}
	}
	var err error
	if newName == "" {
		_, err = store.Forget(oldName)
	} else {
		err = store.Rename(oldName, newName)
	}
	if err != nil {
		inv.app.Out.Warn("The configuration record of '" + oldName + "' was not carried over: " + strings.Join(msgs(err), " "))
	}
}

func fileThere(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
