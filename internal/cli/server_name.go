package cli

// 'tacctl server name [<label>|unset]' (0.2.22): the name this server goes by
// in the console's prompt ('<name>> ') and its notices (the banner of a
// session, the header of 'device client-config'), in place of the host name.
// The setting is server.name of tacctl.yaml: a lower-case DNS label
// (names.ServerNameProblem). With no word it shows the name in effect and
// where it comes from. Only the superuser sets it (the tier table has no row
// for the family). The console reads it from the root side with the rest of
// its policy ('_console-policy' says name=<label> when the setting is there).

import (
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
)

const serverUseName = "name [<label>|unset]"

// serverNameNow is the name in effect and where it comes from: the setting
// server.name, else the host name.
func (inv *invocation) serverNameNow() (name, source string) {
	if n := inv.app.Conf().ServerName(); n != "" {
		return n, "setting"
	}
	return shortHostname(), "host name"
}

// serverName is 'server name [<label>|unset]'.
func (inv *invocation) serverName(args []string) error {
	if len(args) > 1 {
		return inv.usageErr("Usage: tacctl server " + serverUseName)
	}
	a := inv.app
	want := arg(args, 0)
	if want == "" {
		name, source := inv.serverNameNow()
		inv.echo("")
		if source == "setting" {
			inv.echo("  Server name: " + name + "  (the setting " + conf.ServerNameKey + ")")
		} else {
			inv.echo("  Server name: " + name + "  (the host name; none is set: tacctl server name <label>)")
		}
		inv.echo("  The console's prompt and its notices show it.")
		inv.echo("")
		return nil
	}
	if want == "-h" || want == "--help" || want == "help" {
		inv.write(serverHelp())
		return nil
	}
	if err := inv.confReadable(); err != nil {
		return err
	}
	before := a.Conf().ServerName()
	if want == names.ServerNameReserved {
		if before == "" {
			a.Out.Info("No server name is set. Nothing was changed.")
			return nil
		}
		if err := a.Conf().Unset(conf.ServerNameKey); err != nil {
			return err
		}
		inv.detail("server name", kvp("from", before), kvp("to", "-"))
		a.Out.InfoE("Server name removed: the console shows the host name (" + shortHostname() + ") from the next session.")
		return nil
	}
	if p := names.ServerNameProblem(want); p != "" {
		return inv.usageErr("'" + want + "' " + p + ". Nothing was changed.")
	}
	if before == want {
		a.Out.Info("The server name is " + want + " already. Nothing was changed.")
		return nil
	}
	if err := a.Conf().SetValue(conf.ServerNameKey, want); err != nil {
		return err
	}
	inv.detail("server name", kvp("from", or(before, "-")), kvp("to", want))
	a.Out.InfoE("Server name set: " + want + ". The console shows it from the next session.")
	return nil
}
