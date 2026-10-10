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
// vendor that is not read (other), a WTI unit and a device no scope covers
// (a pull refuses it, so it is neither never nor stale).
func configState(e devreg.Entry, rec *devconf.Record) string {
	switch {
	case e.Source == devreg.SourceHost, e.Vendor == "other", e.Vendor == "wti":
		return "-"
	case !e.Configured:
		return "-"
	}
	return string(devconf.Recorded(rec))
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

// configBlock is the 'Configuration' row of 'device show': when, by whom
// and over what the last pull read the device, its result and the state of
// each section.
func configBlock(e devreg.Entry, rec *devconf.Record) string {
	switch {
	case e.Vendor == "wti":
		return "not read (" + wtiUnsupported + ")"
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
				parts = append(parts, n+" "+s.State)
			}
		}
		b.WriteString("; sections: " + strings.Join(parts, ", "))
	}
	return b.String()
}

// listJSON is one device of 'device config list --json'.
type listJSON struct {
	Name      string            `json:"name"`
	Scope     string            `json:"scope"`
	Vendor    string            `json:"vendor"`
	State     string            `json:"state"`
	Result    string            `json:"result,omitempty"`
	Pulled    string            `json:"pulled,omitempty"`
	By        string            `json:"by,omitempty"`
	Transport string            `json:"transport,omitempty"`
	Netconf   string            `json:"netconf,omitempty"`
	Sections  map[string]string `json:"sections,omitempty"`
	DiffersIn []string          `json:"differs_in,omitempty"`
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
	}
	var rows []row
	for _, e := range entries {
		rec, _ := recs.Of(e.Name)
		state := configState(e, rec)
		var differ []string
		if e.Vendor != "wti" && e.Configured {
			if st, err := inv.staleness(store, recs, render, e); err == nil {
				state = string(st)
			}
			if state == string(devconf.StaleDiffers) {
				differ = inv.differingNow(store, rec, render, e)
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
			if !ok || e.Vendor == "wti" || !e.Configured {
				continue
			}
		}
		rows = append(rows, row{e, rec, state, differ})
	}
	if p.Has("--json") {
		out := []listJSON{}
		for _, r := range rows {
			j := listJSON{Name: r.e.Name, Scope: r.e.Scope, Vendor: r.e.Vendor, State: r.state, DiffersIn: r.differ}
			if r.rec != nil {
				j.Result, j.By, j.Transport = r.rec.Result, r.rec.By, r.rec.Transport
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
	tb := ui.NewTable(head, ui.Left("NAME"), ui.Left("SCOPE"), ui.Left("VENDOR"), ui.Left("CONFIG"), ui.Left("PULLED"),
		ui.Left("BY"), ui.Left("VIA"), ui.Left("NETCONF"), ui.Left("DETAIL"))
	for _, r := range rows {
		pulled, by, via, nc, detail := "-", "-", "-", "-", "-"
		if r.rec != nil {
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
			}
		}
		switch {
		case r.e.Vendor == "wti":
			detail = "not read"
		case !r.e.Configured:
			detail = "no scope"
		}
		tb.Add(r.e.Name, dash(r.e.Scope), r.e.Vendor, r.state, pulled, by, via, nc, detail)
	}
	inv.write(tb.String())
	inv.echo("")
	return nil
}

// differingNow are the sections of a device's stored pull that differ from
// today's rendering.
func (inv *invocation) differingNow(store devconf.Store, rec *devconf.Record, render *managedRender, e devreg.Entry) []string {
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
	return differingSections(rs)
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
