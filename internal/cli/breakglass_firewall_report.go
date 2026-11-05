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
	list := strings.Join(addrs, ", ")
	ports := firewall.PortList(res.Ports)
	switch {
	case res.State == firewall.Failed && res.Mode == firewall.Off:
		return []string{
			ui.Red + "Firewall: NOT APPLIED (" + res.Why + ")" + ui.NC,
			ui.Red + "breakglass.firewall is off, but the table inet tacctl could not be removed: it may still refuse the TCP connections of " + list + " on " + ports + "." + ui.NC,
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
// whether the table could not be loaded (the command then exits 1).
func (inv *invocation) firewallListenerNote() (res firewall.Result, failed bool) {
	a := inv.app
	spec := firewall.SpecOf(a.Conf())
	if len(spec.Held) == 0 && !isRegularFile(a.Paths.FirewallRules) {
		return firewall.Result{}, false
	}
	release, err := a.BackendEnv().HoldApply(inv.ctx)
	if err != nil {
		return firewall.Result{}, false
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
	return res, false
}
