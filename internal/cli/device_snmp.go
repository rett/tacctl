package cli

// The device's own name as a hint (docs/plans/0.2.2-plan.md 5.10, D28):
// 'device add' reads sysName.0 from the address next to its host-key scan
// and compares it with the name given; 'device add <address>' offers it as
// the name; 'device check' shows it in an 'SNMP name' row. The hint never
// blocks an add, and nothing of it is stored. The SNMP settings are
// tacctl.yaml's snmp.*, the credentials StateDir/snmp.yaml (config_snmp.go),
// and a scope's own settings and credentials come first (snmp_scope.go, D46);
// app.App's SNMP replaces all of them in the tests.

import (
	"errors"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devreg"
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

// checkSysName is the 'SNMP name' of one device for 'device check'.
type checkSysName struct {
	name    string
	err     error
	problem string
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
			out[i] = checkSysName{name: name, err: err}
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
