package cli

// 'device timeout-scale', 'scope timeout-scale' and 'config devices
// timeout-scale' (0.2.22): the timing scale of a device, of a scope and of the
// whole server (timeout_scale.go has what it is and how it resolves). With no
// value a verb shows the scale in force and where it comes from; a number
// from 1 to 10 sets it; 'clear' removes the device's or the scope's own, so
// the next level decides again. The verbs are the superuser's, as the NETCONF
// service setting's are (no tier row names them); what an engineer needs is in
// 'device show' and 'scope show', which show the scale when it is not 1.

import (
	"strconv"
	"time"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/snmp"
)

const deviceTimeoutScaleUse = "timeout-scale <name> [<n>|clear]"

const deviceTimeoutScaleShort = "Show, set or clear the device's own timing scale, 1-10"

const scopeTimeoutScaleUse = "timeout-scale <scope> [<n>|clear]"

const scopeTimeoutScaleShort = "Show, set or clear the timing scale of the scope's devices, 1-10"

// timeoutScaleWords is the word the second argument of the two verbs takes
// besides the number (the completion lists it).
const timeoutScaleWords = "1|2|3|4|5|6|7|8|9|10|clear"

// parseTimeoutScale reads a scale: a whole number from 1 to 10 written
// plainly.
func parseTimeoutScale(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s || !devssh.ValidTimeoutScale(n) {
		return 0, false
	}
	return n, true
}

// timeoutScaleBad is the refusal of a value that is no scale.
func (inv *invocation) timeoutScaleBad(got, usage string) error {
	return inv.usageErr("The timeout scale is a whole number from "+strconv.Itoa(devssh.MinTimeoutScale)+" to "+
		strconv.Itoa(devssh.MaxTimeoutScale)+", or clear: '"+got+"'", usage)
}

// secondsText is d in whole seconds as a message writes it.
func secondsText(d time.Duration) string { return strconv.Itoa(int(d.Seconds())) + " s" }

// timeoutScaleLines say what a scale of n makes of the timings, for a device
// of scope with the SNMP settings own (the zero deviceSNMPOwn for a scope or
// the server). Nothing is said of a scale of 1: every timing is as it has
// always been.
func (inv *invocation) timeoutScaleLines(n int, scope string, own deviceSNMPOwn) []string {
	if n <= devssh.MinTimeoutScale {
		return nil
	}
	t := devssh.ScanTiming{}.Scaled(n)
	times := " x " + strconv.Itoa(n)
	lines := []string{
		"  ssh and NETCONF connect:    " + secondsText(devssh.ConnectTimeoutFor(n)) + "  (" + secondsText(devssh.DefaultConnectTimeout) + times + ": connect, handshake and first prompt)",
		"  host-key scan:              ssh-keyscan " + secondsText(t.Keyscan) + ", one type " + secondsText(t.KeyscanRetry) +
			"; own client connect " + secondsText(t.Connect) + ", handshake " + secondsText(t.Handshake) + ", each further type " + secondsText(t.Attempt),
	}
	if e, err := inv.snmpEffectiveOwn(scope, own); err == nil {
		got := scaledSNMPTimeout(e.Timeout, n)
		note := strconv.Itoa(e.Timeout) + " s" + times
		if e.Timeout*n > snmp.MaxTimeout {
			note += ", held to the most SNMP takes"
		}
		lines = append(lines, "  SNMP timeout:               "+strconv.Itoa(got)+" s  ("+note+"; at most "+strconv.Itoa(snmp.MaxTimeout)+" s)")
	}
	base := inv.deviceConfigSettings().timeout
	lines = append(lines, "  pull and apply, a device:   "+secondsText(scaledDeviceTimeout(base, n))+"  ("+secondsText(base)+times+
		"; between "+secondsText(deviceTimeoutMin)+" and "+secondsText(deviceTimeoutMax)+"; --timeout of a run replaces it)",
		"  not scaled:                 the confirmed-commit windows (they are timers on the device)")
	return lines
}

// timeoutScaleShow prints the scale in force with where it comes from (named
// is the scope's name for a device, "" for a scope), then what it makes of the
// timings for a device of scope.
func (inv *invocation) timeoutScaleShow(subject, named, scope string, ts timeoutScale, own deviceSNMPOwn) {
	inv.echo("Timeout scale of " + subject + ": " + ts.text(named))
	if ts.N == devssh.MinTimeoutScale {
		inv.echo("  Every timing is as it has always been.")
	}
	for _, l := range inv.timeoutScaleLines(ts.N, scope, own) {
		inv.echo(l)
	}
}

// deviceTimeoutScale is 'device timeout-scale <name> [<n>|clear]'.
func (inv *invocation) deviceTimeoutScale(args []string) error {
	const usage = "Usage: tacctl device " + deviceTimeoutScaleUse
	p, err := inv.deviceParse("timeout-scale", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	if len(p.Args) == 1 {
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		if e.Source == devreg.SourceHost {
			return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; its scope's timeout scale applies ('tacctl scope timeout-scale " + e.Scope + "').")
		}
		own, _ := inv.deviceSNMPOwnOf(e.Device)
		inv.timeoutScaleShow("device '"+e.Name+"'", e.Scope, e.Scope, inv.timeoutScaleOf(e.Scope, e.TimeoutScale), own)
		return nil
	}
	next := 0
	if p.Args[1] != "clear" {
		n, ok := parseTimeoutScale(p.Args[1])
		if !ok {
			return inv.timeoutScaleBad(p.Args[1], usage)
		}
		next = n
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	name, was := d.Name, d.TimeoutScale
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find(name).TimeoutScale = next
		return nil
	}); err != nil {
		return err
	}
	inv.detail("device set", kvp("name", name), kvp("field", "timeout-scale"), kvp("from", scaleWord(was)), kvp("to", scaleWord(next)))
	switch {
	case was == next && next == 0:
		inv.app.Out.Info("Device '" + name + "' has no timeout scale of its own already; nothing was changed.")
	case was == next:
		inv.app.Out.Info("Device '" + name + "' timeout scale is " + strconv.Itoa(next) + " already; nothing was changed.")
	case next == 0:
		inv.app.Out.Info("Device '" + name + "' follows its scope's timeout scale again.")
	default:
		inv.app.Out.Info("Device '" + name + "' timeout scale: " + strconv.Itoa(next) + ".")
	}
	return nil
}

// scaleWord is a scale as the audit line writes it.
func scaleWord(n int) string {
	if n == 0 {
		return "follows-scope"
	}
	return strconv.Itoa(n)
}

// scopeTimeoutScale is 'scope timeout-scale <scope> [<n>|clear]'.
func (inv *invocation) scopeTimeoutScale(args []string) error {
	const usage = "Usage: tacctl scope " + scopeTimeoutScaleUse
	p, err := Parse(scopeSpecs["timeout-scale"], args)
	if err != nil {
		return inv.usageErr(err.Error(), usage)
	}
	scope := p.Args[0]
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	c := inv.app.Conf()
	was := policy.TimeoutScaleOfScope(c, scope)
	if len(p.Args) == 1 {
		inv.timeoutScaleShow("scope '"+scope+"'", "", scope, inv.timeoutScaleOf(scope, 0), deviceSNMPOwn{})
		inv.echo("  A device's own scale ('tacctl device timeout-scale') wins over the scope's.")
		return nil
	}
	next := 0
	if p.Args[1] != "clear" {
		n, ok := parseTimeoutScale(p.Args[1])
		if !ok {
			return inv.timeoutScaleBad(p.Args[1], usage)
		}
		next = n
	}
	switch {
	case next == 0 && !policy.TimeoutScaleScopeSet(c, scope):
		inv.app.Out.Info("Scope '" + scope + "' has no timeout scale of its own already; nothing was changed.")
		return nil
	case next != 0 && next == was:
		inv.app.Out.Info("Scope '" + scope + "' timeout scale is " + strconv.Itoa(next) + " already; nothing was changed.")
		return nil
	case next == 0:
		if err := policy.ClearTimeoutScaleScope(c, scope); err != nil {
			return err
		}
	default:
		if err := policy.SetTimeoutScaleScope(c, scope, next); err != nil {
			return err
		}
	}
	inv.detail("scope timeout-scale", kvp("scope", scope), kvp("from", scaleWord(was)), kvp("to", scaleWord(next)))
	if next == 0 {
		inv.app.Out.Info("Scope '" + scope + "' follows the server's timeout scale again (" + strconv.Itoa(inv.timeoutScaleOf(scope, 0).N) + ").")
		return nil
	}
	inv.app.Out.Info("Scope '" + scope + "' timeout scale: " + strconv.Itoa(next) + ".")
	return nil
}
