package cli

// The device's own name as a hint (docs/plans/0.2.2-plan.md 5.10, D28):
// 'device add' reads sysName.0 from the address next to its host-key scan
// and compares it with the name given; 'device add <address>' offers it as
// the name; 'device check' shows it in an 'SNMP name' row. The hint never
// blocks an add, and nothing of it is stored. The device's own location
// (sysLocation.0, 0.2.3 item 110) is read the same way: 'device add' stores
// it when no --snmp-location is given, 'device check' compares it with the
// registry's in a 'Location' row, and 'device location <name> --from-device'
// stores it on request. The SNMP settings are
// tacctl.yaml's snmp.*, the credentials StateDir/snmp.yaml (config_snmp.go),
// and a scope's own settings and credentials come first (snmp_scope.go, D46);
// app.App's SNMP replaces all of them in the tests.

import (
	"errors"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/ui"
)

// The labels of where a name hint comes from.
const (
	hintSNMP = "SNMP sysName"
	hintNAS  = "NAS-Identifier seen by a scan"
)

// snmpConfig is the lookup the default settings make, or why there is
// none (a fragment that ends in the command that fixes it).
func (inv *invocation) snmpConfig() (snmp.Config, string) { return inv.snmpConfigFor("") }

// errEmptySysName is an answer with no name in it.
var errEmptySysName = errors.New("an empty sysName")

// snmpReason is why a lookup got no name: ” for no answer at all (a
// timeout, an empty sysName), else the error's text.
func snmpReason(err error) string {
	var te *snmp.TimeoutError
	if err == nil || errors.As(err, &te) || errors.Is(err, errEmptySysName) {
		return ""
	}
	return err.Error()
}

// sysName reads the device's sysName (trimmed) with the credentials of the
// device's scope, derived from its address (a device in no scope uses the
// default, D46); a lookup that cannot run is problem, one that ran and got
// no name is err (an empty answer is one).
func (inv *invocation) sysName(addr string) (name, problem string, err error) {
	g, problem := inv.snmpGetterFor(inv.scopeOfAddress(addr))
	if g == nil {
		return "", problem, nil
	}
	name, err = g.SysName(inv.ctx, addr)
	name = strings.TrimSpace(name)
	if err == nil && name == "" {
		err = errEmptySysName
	}
	return name, "", err
}

// errEmptySysLocation is an answer with no location in it.
var errEmptySysLocation = errors.New("an empty sysLocation")

// sysLocation reads the device's sysLocation (trimmed) the way sysName
// reads the name: with the credentials of the device's scope; a lookup
// that cannot run is problem, one that ran and got no location is err (an
// empty answer is errEmptySysLocation).
func (inv *invocation) sysLocation(addr string) (loc, problem string, err error) {
	g, problem := inv.snmpGetterFor(inv.scopeOfAddress(addr))
	if g == nil {
		return "", problem, nil
	}
	loc, err = g.SysLocation(inv.ctx, addr)
	loc = strings.TrimSpace(loc)
	if err == nil && loc == "" {
		err = errEmptySysLocation
	}
	return loc, "", err
}

// locRead is what 'device add' got of the device's own location.
type locRead struct {
	text    string
	problem string
	err     error
}

// readLocation is sysLocation as one value.
func (inv *invocation) readLocation(addr string) locRead {
	text, problem, err := inv.sysLocation(addr)
	return locRead{text: text, problem: problem, err: err}
}

// storable says whether the location the device reports is one the registry
// accepts; one it rejects is returned with the reason (shown, not stored).
func (r locRead) storable() (ok bool, rejected error) {
	if r.problem != "" || r.err != nil {
		return false, nil
	}
	if err := devreg.ValidateLocation(r.text); err != nil {
		return false, err
	}
	return true, nil
}

// printLocation is the line(s) under 'device add's registered line about
// the device's own location (d is the device as registered; stored says
// the location was stored with it). At a terminal an empty answer offers
// to enter one (blank skips); anywhere else it is one hint line. It never
// fails the add: a failed write is a warning.
func (inv *invocation) printLocation(d devreg.Device, r locRead, stored bool) {
	hint := "  Location not set: tacctl device location " + shellquote.Q(d.Name) + " '<text>'"
	switch {
	case stored:
		inv.echo("  Location: " + r.text + " (read from the device)")
	case r.problem != "":
		// SNMP is not set up: the name hint has said so.
	case errors.Is(r.err, errEmptySysLocation):
		pr := inv.app.Prompter()
		if !pr.Interactive() {
			inv.echo(hint)
			return
		}
		inv.echo("  The device reports no location (sysLocation is empty).")
		text := pr.Ask("  Enter one to store, or leave blank to skip: ")
		if text == "" {
			inv.echo(hint)
			return
		}
		if err := devreg.ValidateLocation(text); err != nil {
			inv.write("  " + ui.Yellow + "! Not stored: " + strings.Join(msgs(err), " ") + ui.NC + "\n")
			inv.echo(hint)
			return
		}
		if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
			live := f.Find(d.Name)
			if live == nil {
				return inv.usageErr("Device '" + d.Name + "' not found.")
			}
			live.Location = text
			return nil
		}); err != nil {
			inv.write("  " + ui.Yellow + "! The location was not stored." + ui.NC + "\n")
			inv.echo(hint)
			return
		}
		inv.echo("  Location: " + text)
	case r.err != nil:
		// No answer: the name hint has said so.
	default:
		// A location the device reports and the registry rejects.
		_, bad := r.storable()
		inv.write("  " + ui.Yellow + "! The device reports the location '" + r.text + "', which is not stored: " +
			strings.Join(msgs(bad), " ") + ui.NC + "\n")
		inv.echo(hint)
	}
}

// nameHint is what 'device add' says of the device's own name: the name and
// where it comes from, or the info line for none.
type nameHint struct {
	name, source string
	none         string
}

// lookupNameHint is the hint for addr: its sysName, else the NAS-Identifier
// a scan recorded for it, else the line that says why there is none.
func (inv *invocation) lookupNameHint(addr string) nameHint {
	name, problem, err := inv.sysName(addr)
	if problem == "" && err == nil {
		return nameHint{name: name, source: hintSNMP}
	}
	if s, ok := inv.seenLoad().Of(addr); ok && s.LastNASID != "" {
		return nameHint{name: s.LastNASID, source: hintNAS}
	}
	if problem != "" {
		return nameHint{none: "No name hint: " + problem + "."}
	}
	line := "No SNMP answer from " + addr
	if why := snmpReason(err); why != "" {
		line += " (" + why + ")"
	}
	return nameHint{none: line + "; no name hint."}
}

// printNameHint is the hint under 'device add's registered line: the name
// the device gives itself, and a warning when it is not d's.
func (inv *invocation) printNameHint(d devreg.Device, h nameHint) {
	if h.name == "" {
		inv.app.Out.Info(h.none)
		return
	}
	inv.echo("  The device calls itself '" + h.name + "' (" + h.source + ").")
	if devreg.NameMatches(devreg.Entry{Device: d}, h.name) {
		return
	}
	var fixes []string
	if devreg.ValidateHostname(h.name) == nil {
		fixes = append(fixes, "add --hostname "+h.name)
	}
	if lower := strings.ToLower(h.name); offerable(lower) {
		fixes = append(fixes, "register it as "+lower)
	}
	line := "! That is not the name given or its --hostname"
	if len(fixes) > 0 {
		line += ": " + strings.Join(fixes, ", or ")
	}
	inv.write("  " + ui.Yellow + line + "." + ui.NC + "\n")
}

// offerable reports whether a lowercased sysName may be offered as a
// device name: the name rules, and never a generic one (the registry's
// extra generic names are checked again by the add).
func offerable(name string) bool {
	return devreg.ValidateName(name) == nil && !devreg.IsGeneric(name, nil)
}

// deviceAddOffered is 'device add <address>': the name the device gives
// itself, lowercased, offered at a terminal and taken on 'y' (any other
// answer is no name and no error: nothing is registered). Every other way
// is refused with the usage line; the add's own checks follow.
func (inv *invocation) deviceAddOffered(p Parsed, usage string) (string, nameHint, error) {
	addr, err := devreg.NormalizeAddress(p.Args[0])
	if err != nil {
		return "", nameHint{}, inv.usageErr(append(msgs(err), usage)...)
	}
	if p.Has("--no-lookup") {
		return "", nameHint{}, inv.usageErr("No name given, and --no-lookup reads none from the device.", usage)
	}
	sys, problem, err := inv.sysName(addr)
	switch {
	case problem != "":
		return "", nameHint{}, inv.usageErr("No name given, and there is none to offer: "+problem+".", usage)
	case err != nil:
		why := ""
		if r := snmpReason(err); r != "" {
			why = " (" + r + ")"
		}
		return "", nameHint{}, inv.usageErr("No name given, and no SNMP answer from "+addr+why+" to offer one.", usage)
	}
	h := nameHint{name: sys, source: hintSNMP}
	name := strings.ToLower(sys)
	if !offerable(name) {
		why := "it is a generic name"
		if err := devreg.ValidateName(name); err != nil {
			why = "it is not a valid device name"
		}
		return "", h, inv.usageErr("No name given; the device calls itself '"+sys+"' (SNMP sysName), but "+why+".", usage)
	}
	pr := inv.app.Prompter()
	if !pr.Interactive() {
		return "", h, inv.usageErr("No name given; the device calls itself '"+sys+"' (SNMP sysName). Give the name to register it under it.", usage)
	}
	inv.echo("")
	inv.echo("  The device calls itself '" + sys + "' (SNMP sysName).")
	if !pr.Confirm("  Register " + addr + " as '" + name + "'? [y/N]: ") {
		inv.app.Out.Info("Cancelled; nothing was registered.")
		return "", h, nil
	}
	return name, h, nil
}

// --- device check ----------------------------------------------------------------

// checkSysName is the 'SNMP name' and the 'Location' of one device for
// 'device check'.
type checkSysName struct {
	name    string
	err     error
	problem string
	// loc and locErr are the device's sysLocation, read after its name (a
	// device that did not answer the name is not asked again).
	loc    string
	locErr error
}

// checkSysNames reads the sysName of each registry device of entries, all
// at once (at most 16 in flight); hosts get none.
func (inv *invocation) checkSysNames(entries []devreg.Entry) []checkSysName {
	out := make([]checkSysName, len(entries))
	// The credentials are the device's scope's (D46): one getter per scope.
	type lookup struct {
		g       snmp.Getter
		problem string
	}
	byScope := map[string]lookup{}
	for _, e := range entries {
		if e.Source != devreg.SourceDevice || e.Address == "" {
			continue
		}
		if _, ok := byScope[e.Scope]; !ok {
			g, problem := inv.snmpGetterFor(e.Scope)
			byScope[e.Scope] = lookup{g, problem}
		}
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	for i, e := range entries {
		if e.Source != devreg.SourceDevice || e.Address == "" {
			continue
		}
		g := byScope[e.Scope].g
		if g == nil {
			out[i].problem = byScope[e.Scope].problem
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			name, err := g.SysName(inv.ctx, e.Address)
			name = strings.TrimSpace(name)
			if err == nil && name == "" {
				err = errEmptySysName
			}
			r := checkSysName{name: name, err: err}
			if err != nil && !errors.Is(err, errEmptySysName) {
				r.locErr = err
			} else {
				loc, lerr := g.SysLocation(inv.ctx, e.Address)
				r.loc, r.locErr = strings.TrimSpace(loc), lerr
				if lerr == nil && r.loc == "" {
					r.locErr = errEmptySysLocation
				}
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

// row is the 'SNMP name' row's text (” for none: a host).
func (s checkSysName) row(e devreg.Entry) string {
	switch {
	case e.Source != devreg.SourceDevice:
		return ""
	case s.problem != "":
		return "- (" + s.problem + ")"
	case s.err != nil:
		if why := snmpReason(s.err); why != "" {
			return "no answer (" + why + ")"
		}
		return "no answer"
	case devreg.NameMatches(e, s.name):
		return s.name + "  (match)"
	}
	return s.name + "  (differs)"
}

// locationRow is the 'Location' row's text (” for none: a host): the
// device's reading against the registry's.
func (s checkSysName) locationRow(e devreg.Entry) string {
	reg := strings.TrimSpace(e.Location)
	switch {
	case e.Source != devreg.SourceDevice:
		return ""
	case s.problem != "":
		return "- (" + s.problem + ")"
	case errors.Is(s.locErr, errEmptySysLocation):
		if reg == "" {
			return "not set on the device or in the registry"
		}
		return reg + "  (registry only: the device reports none)"
	case s.locErr != nil:
		if why := snmpReason(s.locErr); why != "" {
			return "no answer (" + why + ")"
		}
		return "no answer"
	case reg == "":
		return s.loc + "  (device only: tacctl device location " + e.Name + " --from-device)"
	case strings.EqualFold(reg, s.loc):
		return s.loc + "  (match)"
	}
	return "differs: device '" + s.loc + "', registry '" + reg + "'"
}

// deviceLocationFromDevice is 'device location <name> --from-device [-y]':
// the device's sysLocation, read now, stored as its location. An empty
// answer, no answer and a value the registry rejects are refused with the
// reason and change nothing; a different registered location is shown
// beside the new one and replaced on 'y' at a terminal, or with -y.
func (inv *invocation) deviceLocationFromDevice(p Parsed, f *devreg.File, res *devreg.Resolver) error {
	usage := "Usage: tacctl device location <name> --from-device [-y]"
	if !p.Has("--from-device") {
		return inv.usageErr("-y answers the question of --from-device.", usage)
	}
	if len(p.Args) != 1 {
		return inv.usageErr("--from-device takes the device's name only.", usage)
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	name := d.Name
	text, problem, rerr := inv.sysLocation(d.Address)
	switch {
	case problem != "":
		return inv.usageErr("Cannot read the location of '"+name+"' from the device: "+problem+".", "Nothing was changed.")
	case errors.Is(rerr, errEmptySysLocation):
		return inv.usageErr("The device '"+name+"' ("+d.Address+") reports no location (its sysLocation is empty). Nothing was changed.",
			"Set one with: tacctl device location "+shellquote.Q(name)+" '<text>'")
	case rerr != nil:
		why := ""
		if r := snmpReason(rerr); r != "" {
			why = " (" + r + ")"
		}
		return inv.usageErr("No SNMP answer from " + d.Address + why + ", so the location of '" + name + "' was not read. Nothing was changed.")
	}
	if err := devreg.ValidateLocation(text); err != nil {
		return inv.usageErr(append([]string{"The device '" + name + "' reports the location '" + text + "', which the registry does not accept:"},
			append(msgs(err), "Nothing was changed.")...)...)
	}
	if d.Location == text {
		inv.app.Out.Info("Device '" + name + "' location is already '" + text + "'; nothing to change.")
		return nil
	}
	if d.Location != "" {
		inv.echo("  Registry: " + d.Location)
		inv.echo("  Device:   " + text)
		if !p.Has("-y") {
			pr := inv.app.Prompter()
			if !pr.Interactive() {
				return inv.usageErr("The registry already has a different location for '" + name + "'. Give -y to replace it with the device's.")
			}
			if !pr.ConfirmPrefix("  Replace the registry's location with the device's? [y/N]: ") {
				inv.app.Out.Info("Aborted.")
				return nil
			}
		}
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		live := f.Find(name)
		if live == nil {
			return inv.usageErr("Device '" + name + "' not found.")
		}
		live.Location = text
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("Device '" + name + "' location set to " + text + " (read from the device).")
	return nil
}
