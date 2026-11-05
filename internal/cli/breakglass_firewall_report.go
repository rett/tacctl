package cli

// The reports of the break-glass firewall: what a hold, a release, a move, a
// restore and a change of listeners say about the table
// (breakglass_firewall.go has the setting and the helpers).

import (
	"context"
	"strings"

	"github.com/rett/tacctl/internal/firewall"
	"github.com/rett/tacctl/internal/ui"
)

// firewallAfter is the After hook of a StoreApply that changes the holds: it
// loads the table for the holds and the setting as they are then, and keeps
// the outcome in *res.
func (inv *invocation) firewallAfter(res *firewall.Result) func(context.Context) {
	return func(ctx context.Context) { *res = inv.firewallEngine().Apply(ctx) }
}

// firewallHoldLines are the lines of the report of a hold: what the table does
// with the connections of addrs. failed says the lines are a red warning and
// the command exits 1. A table with nothing to match (no TCP listener) says
// so in one line.
func firewallHoldLines(res firewall.Result, addrs []string) (lines []string, failed bool) {
	lines, failed = firewallHoldLinesOf(res, addrs)
	return withUnitLine(lines, res), failed
}

func firewallHoldLinesOf(res firewall.Result, addrs []string) (lines []string, failed bool) {
	list := strings.Join(addrs, ", ")
	ports := firewall.PortList(res.Ports)
	switch {
	case res.State == firewall.Failed && !res.Enforces():
		// nothing is to be refused (the setting is off or no listener binds a
		// TCP port), yet a table of an earlier load may still refuse it
		why := "breakglass.firewall is off, but the table inet tacctl could not be removed"
		if res.Mode != firewall.Off {
			why = "no TACACS+ listener binds a TCP port, but the table inet tacctl could not be updated"
		}
		return []string{
			ui.Red + "Firewall: NOT APPLIED (" + res.Why + ")" + ui.NC,
			ui.Red + why + ": it may still refuse the TCP connections of " + list + " on " + ports + "." + ui.NC,
			ui.Red + firewallFix(res) + ui.NC,
		}, true
	case res.State == firewall.Failed:
		return []string{
			ui.Red + "Firewall: NOT APPLIED (" + res.Why + ")" + ui.NC,
			ui.Red + "The server still completes the TCP handshake on " + ports + " for " + list + ", so a device that falls back to its local accounts only when the server is unreachable (WTI \"Fallback Local: On (Transport Failure)\", Junos \"authentication-order [ tacplus password ]\") will not." + ui.NC,
			ui.Red + firewallFix(res) + ui.NC,
		}, true
	case len(res.Ports) == 0:
		return []string{"Firewall: no TACACS+ listener binds a TCP port, so there is nothing to refuse (RADIUS is UDP: the device times out)"}, false
	case res.Mode == firewall.Off:
		return []string{"Firewall: off: the server still completes the TCP handshake on " + ports + " for " + list + " (" + firewall.FixCommand(firewall.Default) + ")"}, false
	}
	return []string{"Firewall: " + list + " refused on " + ports + " (" + res.Mode + ")"}, false
}

// firewallReleaseLines are the lines of the report of a release: the reverse.
// Addresses that stay held in the table are counted.
func firewallReleaseLines(res firewall.Result, addrs []string) (lines []string, failed bool) {
	lines, failed = firewallReleaseLinesOf(res, addrs)
	return withUnitLine(lines, res), failed
}

func firewallReleaseLinesOf(res firewall.Result, addrs []string) (lines []string, failed bool) {
	list := strings.Join(addrs, ", ")
	ports := firewall.PortList(res.Ports)
	switch {
	case res.State == firewall.Failed:
		return []string{
			ui.Red + "Firewall: NOT APPLIED (" + res.Why + ")" + ui.NC,
			ui.Red + "The table inet tacctl may still refuse the TCP connections of " + list + " on " + ports + ", so a device that was released may still not reach this server." + ui.NC,
			ui.Red + firewallFix(res) + ui.NC,
		}, true
	case res.State == firewall.Idle || len(res.Ports) == 0:
		return nil, false
	case res.Mode == firewall.Off:
		return []string{"Firewall: off: no table, nothing to lift (breakglass.firewall is off)"}, false
	}
	line := "Firewall: " + list + " accepted again on " + ports
	if n := len(res.Addrs); n > 0 {
		line += "; " + plurals(n, "other held address stays", "other held addresses stay") + " refused"
	}
	return []string{line}, false
}

// firewallRestoreLines are the lines of the report of a restore: the table
// follows the holds the snapshot brought back, and when it brought none back
// the risk of a failure is the other way, the addresses that were held before
// and may still be refused.
func firewallRestoreLines(res firewall.Result) (lines []string, failed bool) {
	if len(res.Addrs) > 0 {
		return firewallHoldLines(res, res.Addrs)
	}
	if res.State == firewall.Failed {
		return withUnitLine([]string{
			ui.Red + "Firewall: NOT APPLIED (" + res.Why + ")" + ui.NC,
			ui.Red + "No address is held after the restore, but the table inet tacctl could not be updated: it may still refuse the TCP connections of the addresses that were held before on " + firewall.PortList(res.Ports) + "." + ui.NC,
			ui.Red + firewallFix(res) + ui.NC,
		}, res), true
	}
	return withUnitLine(nil, res), false
}

// withUnitLine adds the yellow line for a boot unit that could not be
// installed (the table is loaded, but a reboot loses it).
func withUnitLine(lines []string, res firewall.Result) []string {
	if l := res.UnitLine(); l != "" {
		lines = append(lines, ui.Yellow+"Firewall: "+l+ui.NC)
	}
	return lines
}

// echoFirewall prints lines indented under a report; the red ones carry their
// own colour.
func (inv *invocation) echoFirewall(lines []string) {
	for _, l := range lines {
		inv.echoE("  " + l)
	}
}

// firewallFailedError is the closing line on standard error of a command whose
// hold or release stands but whose table could not be loaded.
func (inv *invocation) firewallFailedError(res firewall.Result) {
	inv.app.Out.Error("The change is recorded, rendered and restarted as the report says, but the firewall table was not loaded (" + res.Why + "): " + firewallFixText(res) + ".")
}

// firewallListenerNote reloads the table after a change of tacquito's
// listeners (the ports the rules match) and says so in one line. It does
// nothing when nothing is held and no table was ever written. It reports
// whether the table could not be loaded (the command then exits 1): the
// table failed to load, or the apply lock could not be taken, in which case
// the listener has changed and the table keeps the old ports.
func (inv *invocation) firewallListenerNote() (res firewall.Result, failed bool) {
	a := inv.app
	spec := firewall.SpecOf(a.Conf())
	if len(spec.Held) == 0 && !isRegularFile(a.Paths.FirewallRules) {
		return firewall.Result{}, false
	}
	release, err := a.BackendEnv().HoldApplyAfter(inv.ctx, "The listener was changed, but the table inet tacctl was not loaded and keeps the old ports.")
	if err != nil {
		return firewall.Result{State: firewall.Failed, Mode: spec.Mode, Addrs: spec.Strings(), Ports: spec.Ports, Why: "the apply lock was not taken"}, true
	}
	defer release()
	res = inv.firewallEngine().Apply(inv.ctx)
	inv.detail("firewall reload", kvp("reason", "listener"), kvp("firewall", firewallWord(res)))
	switch {
	case res.State == firewall.Failed:
		inv.echoE(ui.Red + "Firewall: NOT APPLIED (" + res.Why + "): the table still matches the old ports. " + firewallFixText(res) + "." + ui.NC)
		return res, true
	case res.State == firewall.Applied && len(res.Addrs) > 0:
		a.Out.Info("Firewall: " + strings.Join(res.Addrs, ", ") + " refused on " + firewall.PortList(res.Ports) + " (" + res.Mode + ")")
	}
	if line := res.UnitLine(); line != "" {
		a.Out.Warn("Break-glass firewall: " + line)
	}
	return res, false
}

// firewallCheck is the live table compared with the holds and the setting.
// Only the superuser's view reads it (nft needs root, and a lower tier is told
// nothing of the table): ok is false for a restricted caller.
func (inv *invocation) firewallCheck() (spec firewall.Spec, chk firewall.Check, ok bool) {
	if inv.callerScopes().restricted {
		return firewall.Spec{}, firewall.Check{}, false
	}
	spec = firewall.SpecOf(inv.app.Conf())
	return spec, inv.firewallEngine().Check(inv.ctx), true
}

// firewallState says in one clause what the table does for the held addresses
// and whether it is as it should be: level is "ok", "warn" or "error".
func firewallState(spec firewall.Spec, chk firewall.Check) (text, level string) {
	addrs := strings.Join(spec.Strings(), ", ")
	switch {
	case chk.State == firewall.Differs:
		return "the table inet tacctl differs from the holds and the setting: " + strings.Join(chk.Differences, "; "), "error"
	case chk.State == firewall.Unreadable:
		return spec.Mode + "; the live table was not read (" + chk.Why + ")", "warn"
	case spec.Mode == firewall.Off:
		return "off: the server still completes the TCP handshake of " + addrs + " on " + firewall.PortList(spec.Ports), "warn"
	case len(spec.Ports) == 0:
		return "no TACACS+ listener binds a TCP port, so there is nothing to refuse (RADIUS is UDP: the device times out)", "ok"
	}
	return addrs + " refused on " + firewall.PortList(spec.Ports) + " (" + spec.Mode + ")", "ok"
}

// statusFirewall is the Break-glass firewall line of 'status', after the holds:
// shown when an address is held or the live table differs; green when the
// table is as the holds and the setting ask for, yellow when it is off or was
// not read, red with the differences and the command that fixes them.
func (inv *invocation) statusFirewall() {
	spec, chk, ok := inv.firewallCheck()
	if !ok || (len(spec.Held) == 0 && chk.State != firewall.Differs) {
		return
	}
	text, level := firewallState(spec, chk)
	colour := map[string]string{"ok": ui.Green, "warn": ui.Yellow, "error": ui.Red}[level]
	if level == "error" {
		text += " (" + chk.Fix + ")"
	}
	inv.echoE("    " + colour + "Break-glass firewall: " + text + ui.NC)
}

// listFirewall is the firewall line of 'breakglass list' (the superuser's
// view): what the table does for the held addresses, in the colours of
// status, and the command that fixes a table that differs.
func (inv *invocation) listFirewall() {
	spec, chk, ok := inv.firewallCheck()
	if !ok || (len(spec.Held) == 0 && chk.State != firewall.Differs) {
		return
	}
	text, level := firewallState(spec, chk)
	colour := map[string]string{"ok": ui.Green, "warn": ui.Yellow, "error": ui.Red}[level]
	if level == "error" {
		text += " (" + chk.Fix + ")"
	}
	inv.echoE("  " + colour + "Firewall: " + text + ui.NC)
}
