package cli

// 'config cisco source-interface' (docs/plans/0.2.5-plan.md D119): the
// interface the Cisco devices of a scope take the source address of their
// TACACS+ and RADIUS requests from, one tacctl.yaml key per scope
// (cisco.source_interface.<scope>). It is the one policy value the standard
// Cisco block needs that has no default: unset, the walkthrough prints the
// statement commented with this command (a plan's report warns, when there
// is one), and nothing is rendered or compared. The setter is the superuser's like every
// setting (the tier gate sees 'config cisco', which an engineer may run for
// the walkthrough, so the engineer's part is decided here, the shape of
// 'scope snmp'): an engineer reads the settings of their own scopes.

import (
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/ui"
)

const ciscoSourceInterfaceUse = "tacctl config cisco source-interface [<scope> [<interface>|none]]"

// ciscoSourceInterfaceKey is the tacctl.yaml key of a scope's setting.
func ciscoSourceInterfaceKey(scope string) string { return "cisco.source_interface." + scope }

func ciscoSourceInterfaceUsage() string {
	return "\n" + ui.Bold + "tacctl config cisco source-interface" + ui.NC + " — the interface a scope's Cisco devices source their server requests from\n" + `
Usage:
  ` + ciscoSourceInterfaceUse + `

  (no arguments)          Show the setting of every scope (an engineer: the scopes of their own)
  <scope>                 Show the scope's setting
  <scope> <interface>     Set it: the full interface name as IOS prints it, such as Loopback0 or
                          GigabitEthernet0/0/1 (not lo0 or gi0/1: IOS stores the long form, so
                          a device would compare different for ever)
  <scope> none            Unset it (the standard then renders no source-interface line)

The interface types are Loopback, GigabitEthernet, TenGigabitEthernet, TwentyFiveGigE,
FortyGigabitEthernet, HundredGigE, FastEthernet, Ethernet, Serial, Vlan, Port-channel, Tunnel,
BVI and Management, followed by the number (slot, port, channel and sub-interface separators
are / . :), with the capitals IOS prints.

The standard Cisco block pins the TACACS+ (and RADIUS) client of every device in the scope to
this interface ('ip tacacs source-interface <interface>', 'ip radius source-interface
<interface>'), so the server sees one stable address per device: the one its prefix lists
match. Unset, nothing is rendered or compared and the walkthrough prints the line commented
with this command; a source interface the device already has is left alone. In tacctl.yaml
as cisco.source_interface.<scope>. Setting it is the superuser's.

Examples:
  tacctl config cisco source-interface
  tacctl config cisco source-interface prod Loopback0
  tacctl config cisco source-interface prod none

`
}

// configCiscoSourceInterface is 'config cisco source-interface ...'; args
// are what follows the word.
func (inv *invocation) configCiscoSourceInterface(args []string) error {
	switch arg(args, 0) {
	case "-h", "--help", "help":
		inv.write(ciscoSourceInterfaceUsage())
		return nil
	}
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", "Usage: "+ciscoSourceInterfaceUse)
	}
	scope, value := arg(args, 0), arg(args, 1)
	f := inv.callerScopes()
	if scope == "" {
		return inv.configCiscoSourceInterfaceList(f)
	}
	if f.restricted {
		if err := inv.scopeNotFound(f, scope); err != nil {
			return err
		}
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	path := ciscoSourceInterfaceKey(scope)
	if value == "" {
		inv.echo("")
		inv.echo("  Scope '" + scope + "'")
		if cur := inv.confGet(path, ""); cur != "" {
			inv.echo("  Cisco source interface: " + cur + "   (tacctl.yaml: " + path + ")")
		} else {
			inv.echo("  Cisco source interface: not set   (nothing is rendered or compared)")
		}
		inv.echo("")
		inv.echo("  Usage: tacctl config cisco source-interface " + scope + " <interface>|none")
		inv.echo("")
		return nil
	}
	if f.restricted {
		return inv.deniedUsage(reasonSuperuser, "The engineer tier reads the source interface: tacctl config cisco source-interface ["+scope+
			"]. Setting it is the superuser's. Nothing was changed.")
	}
	if value == "none" {
		if err := inv.app.Conf().Unset(path); err != nil {
			return err
		}
		inv.app.Out.InfoE("Scope '" + scope + "' Cisco source interface cleared.")
		inv.echo("")
		inv.echo("  The configuration of the scope renders no source-interface line any more; a device")
		inv.echo("  keeps the line it has until it is removed there.")
		inv.echo("")
		return nil
	}
	if err := inv.app.Conf().Set(path, value); err != nil {
		return err
	}
	inv.app.Out.InfoE("Scope '" + scope + "' Cisco source interface set to " + value + ".")
	inv.echo("")
	inv.echo("  Re-run 'tacctl config cisco --scope " + scope + "' (or 'tacctl device config show <device>') to see")
	inv.echo("  'ip tacacs source-interface " + value + "' ('ip radius source-interface' for RADIUS), and put it on each")
	inv.echo("  device of the scope. The server then sees that interface's address: it must be inside a")
	inv.echo("  prefix of the scope ('tacctl scope prefixes " + scope + " list').")
	inv.echo("")
	return nil
}

// configCiscoSourceInterfaceList prints the setting of every scope the
// caller may read.
func (inv *invocation) configCiscoSourceInterfaceList(f scopeFilter) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	scopes := m.ScopesByRouting()
	sort.Strings(scopes)
	width := 0
	for _, s := range scopes {
		if f.allows(s) {
			width = max(width, len(s))
		}
	}
	inv.echo("")
	inv.echo("  Cisco source interface, per scope (tacctl.yaml: cisco.source_interface.<scope>)")
	shown := 0
	for _, s := range scopes {
		if !f.allows(s) {
			continue
		}
		shown++
		v := inv.confGet(ciscoSourceInterfaceKey(s), "")
		if v == "" {
			v = "not set"
		}
		inv.echo("    " + s + strings.Repeat(" ", width-len(s)) + "  " + v)
	}
	if shown == 0 {
		inv.echo("    (no scope)")
	}
	inv.echo("")
	inv.echo("  Usage: tacctl config cisco source-interface <scope> <interface>|none")
	inv.echo("")
	return nil
}
