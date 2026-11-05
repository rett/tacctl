package cli

// The break-glass firewall (0.2.24): the nftables table 'inet tacctl' that
// refuses the TCP connections of the held addresses (internal/firewall), and
// its setting, 'tacctl config breakglass-firewall reject|drop|off'
// (breakglass.firewall in tacctl.yaml). A hold takes an address out of the
// scopes' prefixes, so FreeRADIUS (UDP) ignores the device; tacquito listens on
// TCP, where the kernel completes the handshake and tacquito accepts and closes
// the connection, and a device whose fallback needs the server to be
// unreachable (WTI "Fallback Local: On (Transport Failure)", Junos
// authentication-order [ tacplus password ]) never uses its local accounts. The
// table is loaded at the point the backends restart (backend.ApplyOptions.After),
// on every hold, release, move of a held device, rename, restore, listener
// change and setting change, and reported beside them; when it cannot be, the
// hold stands, the report says so in red and the command exits 1.

import (
	"strings"

	"github.com/rett/tacctl/internal/firewall"
	"github.com/rett/tacctl/internal/ui"
)

const (
	breakglassFirewallUse   = "breakglass-firewall [reject|drop|off]"
	breakglassFirewallUsage = "Usage: tacctl config " + breakglassFirewallUse
)

// firewallEngine is the table's engine over the invocation's runner, paths and
// tacctl.yaml.
func (inv *invocation) firewallEngine() *firewall.Engine {
	a := inv.app
	return &firewall.Engine{Runner: a.Runner, Paths: a.Paths, Conf: a.Conf()}
}

// firewallWord is the value of firewall= in the audit lines of a hold and a
// release: the setting that was applied (reject, drop, off), or failed.
func firewallWord(res firewall.Result) string {
	if !res.OK() {
		return "failed"
	}
	return res.Mode
}

// firewallFix is the way out of a table that could not be loaded: install nft
// when it is missing, then the setting command, which loads the table again
// even when the setting is unchanged.
func firewallFix(res firewall.Result) string {
	cmd := firewall.FixCommand(res.Mode)
	if res.NftMissing {
		return "Fix: " + firewall.InstallCommand + ", then " + cmd
	}
	return "Fix: remove the cause above, then " + cmd + " (it loads the table again even when the setting is unchanged)"
}

// --- config breakglass-firewall ---------------------------------------------------

// configBreakglassFirewall shows breakglass.firewall and where it comes from,
// or sets it: reject (the default) removes the key, drop and off write it.
// Either way the table is loaded again at once, so the command is also the
// repair of a table that was not loaded (nft installed late, a table removed
// by hand): it says what it did, and exits 1 when the table could not be
// loaded while an address is held.
func (inv *invocation) configBreakglassFirewall(args []string) error {
	if len(args) > 1 {
		return inv.usageErr("Unknown argument: '"+args[1]+"'", breakglassFirewallUsage)
	}
	a := inv.app
	c := a.Conf()
	was := firewall.Mode(c)
	v := arg(args, 0)
	if v == "" {
		src := "default"
		if c.HasOverride(confBreakglassFirewall) {
			src = "tacctl.yaml"
			if raw, _ := c.Value(confBreakglassFirewall); !firewall.ValidMode(firewallText(raw)) {
				src = "tacctl.yaml holds a value that is not reject, drop or off, read as reject; 'tacctl config validate' says more"
			}
		}
		spec := firewall.SpecOf(c)
		inv.echo("")
		inv.echo("  Break-glass firewall: " + was + "   (" + src + ")")
		inv.echo("  (reject: the TCP connections of a held address to tacquito get a reset; drop: they are dropped;")
		inv.echo("  off: no table, the server completes the handshake and tacquito closes the connection)")
		if held := spec.Strings(); len(held) > 0 {
			inv.echo("  Held now: " + strings.Join(held, ", ") + "; ports " + firewall.PortList(spec.Ports))
		} else {
			inv.echo("  Held now: none")
		}
		if chk := inv.firewallEngine().Check(inv.ctx); chk.State == firewall.Unreadable {
			inv.echo("  Table:    not read (" + chk.Why + ")")
		} else if chk.State == firewall.Differs {
			inv.echoE("  " + ui.Red + "Table:    differs: " + strings.Join(chk.Differences, "; ") + " (" + chk.Fix + ")" + ui.NC)
		} else {
			inv.echo("  Table:    as the holds and the setting ask for")
		}
		inv.echo("")
		inv.echo("  " + breakglassFirewallUsage)
		inv.echo("")
		return nil
	}
	if !firewall.ValidMode(v) {
		return inv.usageErr("Invalid value: '"+v+"'. Use: "+strings.Join(firewall.Modes, ", "), breakglassFirewallUsage)
	}
	release, err := a.BackendEnv().HoldApply(inv.ctx)
	if err != nil {
		return err
	}
	defer release()
	if v == firewall.Default {
		err = c.Unset(confBreakglassFirewall)
	} else {
		err = c.Set(confBreakglassFirewall, v)
	}
	if err != nil {
		return err
	}
	res := inv.firewallEngine().Apply(inv.ctx)
	inv.detail("config breakglass-firewall", kvp("from", was), kvp("to", v), kvp("firewall", firewallWord(res)))
	inv.echo("")
	if v == was {
		a.Out.Info("breakglass.firewall is " + v + " already; the table was loaded again.")
	} else {
		a.Out.Info("breakglass.firewall is " + v + " (it was " + was + ").")
	}
	return inv.firewallSettingReport(res)
}

// firewallText is a setting value as text ("" when it is not a string).
func firewallText(v any) string {
	s, _ := v.(string)
	return s
}

// confBreakglassFirewall is the key of the setting.
const confBreakglassFirewall = "breakglass.firewall"

// firewallSettingReport says what the table is now, after a change of the
// setting or a listener, and ends the command: exit 1 when it could not be
// loaded while an address is held.
func (inv *invocation) firewallSettingReport(res firewall.Result) error {
	held := res.Addrs
	switch {
	case res.State == firewall.Failed && (len(held) > 0 || res.Mode == firewall.Off):
		for _, l := range []string{
			"Firewall: NOT APPLIED (" + res.Why + ")",
			"The table inet tacctl does not say what breakglass.firewall asks for; " + firewallFixText(res),
		} {
			inv.echoE(ui.Red + l + ui.NC)
		}
		inv.echo("")
		inv.app.Out.Error("The firewall table was not loaded (" + res.Why + "): " + strings.TrimPrefix(firewallFix(res), "Fix: ") + ".")
		return exit(1)
	case res.State == firewall.Idle || res.State == firewall.Failed:
		inv.echo("Firewall: nothing is held and nft is not installed, so no table is loaded; the next hold needs it (" + firewall.InstallCommand + ", then " + firewall.FixCommand(res.Mode) + ").")
	case res.State == firewall.Removed:
		inv.echo("Firewall: off: the table inet tacctl is removed; the server completes the TCP handshake of a held address again (the 0.2.23 behaviour).")
	case len(held) == 0:
		inv.echo("Firewall: the table inet tacctl is loaded with " + res.Mode + " on " + firewall.PortList(res.Ports) + " and no held address; a hold fills it.")
	default:
		inv.echo("Firewall: " + strings.Join(held, ", ") + " refused on " + firewall.PortList(res.Ports) + " (" + res.Mode + ")")
	}
	inv.echo("")
	return nil
}

// firewallFixText is firewallFix without the "Fix: " lead.
func firewallFixText(res firewall.Result) string {
	return strings.TrimPrefix(firewallFix(res), "Fix: ")
}
