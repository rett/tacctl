package cli

// 'device sync <selection> [--apply] [--overwrite]' (docs/plans/0.2.9-
// rollout-plan.md D137, D141): the registry's EMPTY hostname, location and
// description fields filled from what each device said of itself in its last
// pull record (its 'system host-name' with 'domain-name', its 'snmp location'
// and its 'snmp description'). It never logs in: it reads the records and the
// stored sections only. The preview comes first; --apply writes, after one
// question, in ONE registry write under the registry's own lock (never an
// import of a re-serialised file). A set field is replaced only with
// --overwrite, which shows the old value. The name, address, vendor and scope
// are never touched, and what a device reports is checked before it is shown
// or stored: a value with control characters, or one the registry would not
// accept from a person, is listed as refused and never written.
//
// A hostname is filled only when the device's name is a DNS name (it has a
// dot) AND the system resolver answers it with the device's registered
// address and no other: the registry's hostname is where tacctl connects
// (devreg.SSHTarget dials it instead of the address, and the login's
// password goes with it), so a name the device merely reports would send
// later logins wherever DNS points. A lookup that fails, an answer without
// the address and an answer with any other address are "not filled". The
// same rule holds for --overwrite, which never replaces a hostname with an
// unresolved one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// syncUse is the usage line of the verb.
const syncUse = "Usage: tacctl device sync <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> [--apply] [--overwrite] [--json] [-y]"

// syncResolveTimeout bounds one lookup of a reported host name.
const syncResolveTimeout = 5 * time.Second

// The actions of one field.
const (
	syncFill    = "fill"
	syncReplace = "replace"
	syncSame    = "same"
	syncKeep    = "keep"
	syncNone    = "none"
	syncRefused = "refused"
)

// syncField is one registry field of one device.
type syncField struct {
	Field  string `json:"field"`
	Now    string `json:"now,omitempty"`
	Device string `json:"device,omitempty"`
	Action string `json:"action"`
	Why    string `json:"why,omitempty"`

	value string // the value to store, when the action writes
	old   string // the registry's value when the preview was made
}

// writes reports whether the field is written under --apply.
func (f syncField) writes() bool { return f.Action == syncFill || f.Action == syncReplace }

// syncDevice is one device of the selection.
type syncDevice struct {
	Name    string      `json:"name"`
	Pulled  string      `json:"pulled,omitempty"`
	Login   string      `json:"login,omitempty"`
	Model   string      `json:"model,omitempty"`
	Release string      `json:"release,omitempty"`
	Serial  string      `json:"serial,omitempty"`
	Fields  []syncField `json:"fields,omitempty"`
	Skipped string      `json:"skipped,omitempty"`
}

// deviceSyncRun is one run.
type deviceSyncRun struct {
	inv                              *invocation
	user                             string
	apply, overwrite, asJSON, yes    bool
	devices                          []*syncDevice
	skippedVendor                    []string
	applied, appliedDevs, concurrent int
	// appliedNames are the devices written, for the audit line.
	appliedNames []string
}

// deviceSync is 'device sync'.
func (inv *invocation) deviceSync(args []string) error {
	p, err := Parse(deviceSpecs["sync"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.argErr(msg, syncUse)
	}
	if err := inv.deviceVerbAllowed("device", "sync", tier.Superuser); err != nil {
		return err
	}
	s := &deviceSyncRun{inv: inv, user: inv.sudoUser(), apply: p.Has("--apply"), overwrite: p.Has("--overwrite"),
		asJSON: p.Has("--json"), yes: p.Has("-y")}
	sel, err := s.selection(p)
	if err != nil {
		return err
	}
	if s.apply && !s.yes && !inv.app.Prompter().Interactive() {
		return inv.argErr("No terminal to answer the question on: --apply without one needs -y (the preview needs neither).", syncUse)
	}
	if err := s.collect(sel); err != nil {
		return err
	}
	return s.run(s.asJSON)
}

// selection reads the selectors: names, --all, --scope, --vendor.
func (s *deviceSyncRun) selection(p Parsed) (selection, error) {
	inv := s.inv
	var sel selection
	seen := map[string]bool{}
	for _, a := range p.Args {
		for _, n := range strings.Split(a, ",") {
			n = strings.TrimSpace(n)
			if n != "" && !seen[strings.ToLower(n)] {
				seen[strings.ToLower(n)] = true
				sel.names = append(sel.names, n)
			}
		}
	}
	sel.all, sel.scope, sel.vendor = p.Has("--all"), p.Value("--scope"), p.Value("--vendor")
	filters := p.Has("--scope") || p.Has("--vendor")
	switch {
	case len(sel.names) > 0 && (sel.all || filters):
		return sel, inv.argErr("Name the devices, or select them with --all, --scope or --vendor, not both.", syncUse)
	case sel.all && filters:
		return sel, inv.argErr("--all is every device; drop it to select with --scope or --vendor.", syncUse)
	case len(sel.names) == 0 && !sel.all && !filters:
		return sel, inv.argErr("Name the devices to sync, or select them with --all, --scope <name> or --vendor <vendor>.", syncUse)
	case p.Has("--vendor") && !slices.Contains(sortedVendors(), sel.vendor):
		return sel, inv.argErr("--vendor takes cisco, juniper or wti: '"+sel.vendor+"'", syncUse)
	}
	return sel, nil
}

// collect reads the records of the selection and works out each field.
func (s *deviceSyncRun) collect(sel selection) error {
	inv := s.inv
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	var entries []devreg.Entry
	if len(sel.names) > 0 {
		for _, n := range sel.names {
			e, err := inv.deviceFind(res, n)
			if err != nil {
				return err
			}
			if e.Source == devreg.SourceHost {
				return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; sync fills a device's fields from its pull record.")
			}
			entries = append(entries, e)
		}
	} else {
		for _, e := range res.Visible(inv.deviceFilter()) {
			switch {
			case e.Source != devreg.SourceDevice:
			case sel.scope != "" && e.Scope != sel.scope:
			case sel.vendor != "" && e.Vendor != sel.vendor:
			default:
				entries = append(entries, e)
			}
		}
	}
	store := inv.configStore()
	recs, err := store.Load()
	if err != nil {
		return err
	}
	for _, e := range entries {
		d := &syncDevice{Name: e.Name}
		s.devices = append(s.devices, d)
		rec, ok := recs.Of(e.Name)
		switch {
		case e.Vendor != "juniper":
			d.Skipped = "only a Junos device's record is read (vendor " + e.Vendor + ")"
			s.skippedVendor = append(s.skippedVendor, e.Name)
			continue
		case !ok || rec.Pulled.IsZero():
			d.Skipped = "no pull record: tacctl device config pull " + e.Name + " (or device collect --register)"
			continue
		}
		d.Pulled = rec.Pulled.UTC().Format("2006-01-02 15:04")
		d.Login = rec.Login
		d.Model, d.Release, d.Serial = devText(rec.Model), devText(rec.Release), devText(rec.Serial)
		secs, err := store.Sections(e.Name, e.Vendor)
		if err != nil {
			d.Skipped = "its stored sections cannot be read: " + strings.Join(msgs(err), " ")
			continue
		}
		var location, description string
		if sec, ok := secs["snmp"]; ok {
			location = sectionValue(sec.Lines, "snmp location")
			description = sectionValue(sec.Lines, "snmp description")
		}
		d.Fields = []syncField{
			s.field("hostname", e.Hostname, rec.Hostname, e.Address),
			s.field("location", e.Location, location, ""),
			s.field("description", e.Description, description, ""),
		}
	}
	return nil
}

// sectionValue is the value of the first '<path> <value>' statement of a
// section's lines, the quotes of the statement removed: "" when it has none.
func sectionValue(lines []string, path string) string {
	for _, l := range lines {
		v, ok := strings.CutPrefix(strings.TrimSpace(l), "set "+path+" ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if rest, ok := strings.CutPrefix(v, `"`); ok {
			var b strings.Builder
			for i := 0; i < len(rest); i++ {
				switch {
				case rest[i] == '\\' && i+1 < len(rest) && (rest[i+1] == '"' || rest[i+1] == '\\'):
					i++
					b.WriteByte(rest[i])
				case rest[i] == '"':
					return b.String()
				default:
					b.WriteByte(rest[i])
				}
			}
			return b.String()
		}
		return v
	}
	return ""
}

// capText is s cut to n characters.
func capText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// unsafeText reports why device-reported text is not stored: a control
// character (a newline, a terminal escape), invalid UTF-8.
func unsafeText(s string) string {
	if !utf8.ValidString(s) {
		return "it is not valid UTF-8"
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return "it contains control characters"
		}
	}
	return ""
}

// resolvesToOnly reports whether the system resolver (resolve; nil is the
// system's own) answers host with the address addr and no other: the one
// condition under which a device-reported name becomes the registry's
// hostname. A lookup failure, an answer without addr, an answer with any
// other address and one that is not an address at all are all false.
func resolvesToOnly(ctx context.Context, resolve func(context.Context, string) ([]string, error), host, addr string) bool {
	want := net.ParseIP(strings.TrimSpace(addr))
	if want == nil {
		return false
	}
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(ctx, syncResolveTimeout)
	defer cancel()
	got, err := resolve(ctx, host)
	if err != nil || len(got) == 0 {
		return false
	}
	for _, g := range got {
		ip := net.ParseIP(g)
		if ip == nil || !ip.Equal(want) {
			return false
		}
	}
	return true
}

// field works out one field: now is the registry's value, says the device's;
// addr is the device's registered address, which a hostname must resolve to.
func (s *deviceSyncRun) field(name, now, says, addr string) syncField {
	f := syncField{Field: name, Now: devText(now), Device: devText(says), old: now}
	if says == "" {
		f.Action = syncNone
		return f
	}
	var verr error
	why := unsafeText(says)
	if why == "" {
		var d devreg.Device
		verr = setField(&d, name, says, false)
		switch {
		case verr != nil:
			why = strings.Join(msgs(verr), " ")
		case name == "hostname" && !strings.Contains(says, "."):
			why = "it is a bare name, not a DNS name (the device states no domain-name)"
		}
	}
	switch {
	case why != "":
		f.Action, f.Why = syncRefused, capText(cleanLine(why), 110)
	case now == says:
		f.Action = syncSame
	case now != "" && !s.overwrite:
		f.Action, f.Why = syncKeep, "set; --overwrite replaces it"
	case name == "hostname" && !resolvesToOnly(s.inv.ctx, s.inv.app.Resolve, says, addr):
		// never a name the resolver does not tie to this device's address
		f.Action, f.Why = syncRefused, "does not resolve: not filled"
	case now == "":
		f.Action, f.value = syncFill, says
	default:
		f.Action, f.value = syncReplace, says
	}
	if name == "hostname" && f.writes() {
		f.Why = "resolves to the address"
	}
	return f
}

// changes are the fields the run would write.
func (s *deviceSyncRun) changes() (devs, fields int) {
	for _, d := range s.devices {
		n := 0
		for _, f := range d.Fields {
			if f.writes() {
				n++
			}
		}
		if n > 0 {
			devs++
			fields += n
		}
	}
	return devs, fields
}

// run prints the preview and, with --apply, writes.
func (s *deviceSyncRun) run(asJSON bool) error {
	inv := s.inv
	devs, fields := s.changes()
	if !s.apply || fields == 0 {
		return s.finish(asJSON, devs, fields)
	}
	if !asJSON {
		s.print()
	}
	replaced := 0
	for _, d := range s.devices {
		for _, f := range d.Fields {
			if f.Action == syncReplace {
				replaced++
			}
		}
	}
	q := fmt.Sprintf("Write %d field(s) on %d device(s) of the registry", fields, devs)
	if replaced > 0 {
		q += fmt.Sprintf(", %d of them replacing a value that is set", replaced)
	}
	if !s.yes && !inv.app.Prompter().ConfirmPrefix("  "+q+"? [y/N]: ") {
		inv.app.Out.Info("Aborted; nothing was written.")
		return nil
	}
	if err := s.write(); err != nil {
		inv.app.Audit().Line(audit.Warning, "device sync", audit.Pair("user", s.user), audit.Pair("devices", "0"), audit.Pair("fields", "0"),
			audit.Pair("names", ""), audit.Pair("result", "failed"), audit.Pair("reason", failReason(err, "store")))
		return err
	}
	inv.app.Audit().Line(audit.Info, "device sync", audit.Pair("user", s.user), audit.Pair("devices", strconv.Itoa(s.appliedDevs)),
		audit.Pair("fields", strconv.Itoa(s.applied)), audit.Wide("names", namesList(s.appliedNames, 20)), audit.Pair("result", "ok"))
	return s.finish(asJSON, devs, fields)
}

// write is the one registry write, under the registry's lock: each field is
// checked again against the live file, so a value set since the preview is
// not overwritten.
func (s *deviceSyncRun) write() error {
	inv := s.inv
	_, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		s.applied, s.appliedDevs, s.concurrent = 0, 0, 0
		s.appliedNames = nil
		for _, sd := range s.devices {
			dev := f.Find(sd.Name)
			n := 0
			for i := range sd.Fields {
				sf := &sd.Fields[i]
				if !sf.writes() {
					continue
				}
				if dev == nil {
					s.concurrent++
					continue
				}
				cur := fieldValue(dev, sf.Field)
				if (sf.Action == syncFill && cur != "") || (sf.Action == syncReplace && cur != sf.old) {
					s.concurrent++
					continue
				}
				if err := setField(dev, sf.Field, sf.value, false); err != nil {
					s.concurrent++
					continue
				}
				n++
			}
			if n > 0 {
				s.applied += n
				s.appliedDevs++
				s.appliedNames = append(s.appliedNames, sd.Name)
			}
		}
		if s.applied == 0 {
			return errNothingToFill
		}
		return nil
	})
	if errors.Is(err, errNothingToFill) {
		return nil
	}
	return err
}

// finish prints the result (the preview when nothing was applied).
func (s *deviceSyncRun) finish(asJSON bool, devs, fields int) error {
	inv := s.inv
	if asJSON {
		out := struct {
			Devices []*syncDevice `json:"devices"`
			Apply   bool          `json:"apply"`
			Fields  int           `json:"fields"`
			Written int           `json:"written"`
		}{Devices: s.devices, Apply: s.apply, Fields: fields, Written: s.applied}
		if out.Devices == nil {
			out.Devices = []*syncDevice{}
		}
		b, _ := json.Marshal(out)
		inv.write(string(b) + "\n")
		return nil
	}
	if !s.apply || fields == 0 {
		s.print()
	}
	switch {
	case fields == 0:
		inv.echo("  Nothing to fill: every field the device states is set already or refused.")
	case !s.apply:
		inv.echo(fmt.Sprintf("  %d field(s) on %d device(s) would be written. Write them with --apply.", fields, devs))
	default:
		inv.app.Out.Info(fmt.Sprintf("Wrote %d field(s) on %d device(s).", s.applied, s.appliedDevs))
		if s.concurrent > 0 {
			inv.app.Out.Warn(fmt.Sprintf("%d field(s) changed in the registry since the preview and were left as they are; run it again.", s.concurrent))
		}
	}
	inv.echo("")
	return nil
}

// print is the preview: the fields, then the facts that are not written.
func (s *deviceSyncRun) print() {
	inv := s.inv
	inv.echo("")
	t := ui.NewTable("Registry fields from the last pull records", ui.Left("DEVICE"), ui.Left("FIELD"), ui.Left("REGISTRY"),
		ui.Left("DEVICE SAYS"), ui.Left("ACTION"))
	rows := 0
	for _, d := range s.devices {
		for _, f := range d.Fields {
			act := f.Action
			if f.Why != "" {
				act += ": " + f.Why
			}
			t.Add(d.Name, f.Field, dash(f.Now), dash(f.Device), act)
			rows++
		}
	}
	if rows > 0 {
		inv.write(t.String())
		inv.echo("")
	}
	facts := ui.NewTable("Facts of the records (the record's, not written to the registry)", ui.Left("DEVICE"), ui.Left("PULLED"),
		ui.Left("LOGIN"), ui.Left("MODEL"), ui.Left("RELEASE"), ui.Left("SERIAL"))
	n := 0
	for _, d := range s.devices {
		if d.Skipped != "" {
			continue
		}
		facts.Add(d.Name, d.Pulled, dash(d.Login), dash(d.Model), dash(d.Release), dash(d.Serial))
		n++
	}
	if n > 0 {
		inv.write(facts.String())
		inv.echo("")
	}
	for _, d := range s.devices {
		if d.Skipped != "" {
			inv.echo("  " + d.Name + ": skipped: " + d.Skipped)
		}
	}
	if len(s.devices) == 0 {
		inv.echo("  No device matches the selection.")
	}
	if len(s.devices) > 0 {
		inv.echo("  Not touched: name, address, vendor and scope. Refused values are not written.")
	}
}
