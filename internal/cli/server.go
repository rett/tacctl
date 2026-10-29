package cli

// 'tacctl server addresses [list]|add <ip>|remove <ip>|replace <ip>' (0.2.21):
// the address devices and hosts reach this server at, the setting
// server.addresses of tacctl.yaml (a list so that more than one can be held
// later; this release holds exactly one, so 'add' while one is set is
// refused and 'remove' of the only one is refused: the server needs an
// address, and 'replace' changes it). The verb is the superuser's (the tier
// table has no row for it, as for 'scope prefixes'); 'list' changes nothing.
//
// A change runs in one apply: a snapshot, then the key, this server's registry
// entry, the managed scope's prefixes and the server's own PAM and accounts,
// all by the enrolment of this server (hostEnrollRun), then the follow-ups
// once. 'host enroll --local --server <address>' with an address that is not
// the recorded one is this change too (hostEnroll calls serverAddressApply),
// so the two cannot differ.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

const (
	serverUseAddresses = "addresses [list|add <ip>[,<ip>...]|remove <ip>[,<ip>...]|replace <ip>[,<ip>...]]"
	serverUsage        = "Usage: tacctl server " + serverUseAddresses
)

// The refusals of the one-address limit; a later release lifts it.
const (
	serverOnlyOneText = "only one server address is supported yet"
	serverAddUseText  = serverOnlyOneText + "; use replace"
	serverNeedsText   = "the server needs an address; use replace"
)

// serverFollowUps is what is left to do after the address changed, said once.
const serverFollowUps = "Re-point the devices and hosts at the new address: tacctl host sync --all; the device walkthroughs name the new address"

// serverSpecs are the arguments of each verb (completion and parsing).
var serverSpecs = map[string]Spec{
	"addresses": {MaxArgs: 2, Args: []string{"list|add|remove|replace", ""}},
}

// serverRows are the family's rows: the forms of its verb, with one line each.
var serverRows = [][2]string{
	{"addresses list", "Show the address devices and hosts reach this server at (no word: the same)"},
	{"addresses add <ip>[,<ip>...]", "Set the address when none is set (one is held for now)"},
	{"addresses remove <ip>[,<ip>...]", "Take an address out (the only one stays: use replace)"},
	{"addresses replace <ip>[,<ip>...]", "Change the address, on this server's own login too"},
}

func init() {
	registerFamily(serverCmd)
	registerSpecs("server", serverSpecs)
	shellHelpBlocks["server"] = func(*invocation) string { return serverHelp() }
}

func serverCmd(inv *invocation) *cobra.Command {
	c := verb("server <subcommand>", "This server's settings (addresses: where devices and hosts reach it)")
	c.RunE = inv.native(withPreflight, inv.server)
	c.AddCommand(withRun(verb(serverUseAddresses, "The address devices and hosts reach this server at"),
		inv.native(withPreflight, func(args []string) error {
			return inv.server(append([]string{"addresses"}, args...))
		})))
	return c
}

// serverHelp is the usage of the family.
func serverHelp() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Server Settings" + ui.NC + "\n\nUsage: tacctl server <subcommand> [arguments]\n\nSubcommands:\n")
	for _, r := range serverRows {
		fmt.Fprintf(&b, "  %-36s  %s\n", r[0], r[1])
	}
	b.WriteString(`
The address is the one the devices' walkthroughs (config cisco, juniper, wti),
'config linux script' and 'host enroll' tell a device or host to authenticate
against, unless --server names another for that run. It is an IP address,
which may be behind NAT or a VPN and need not be on this machine (not a host
name, 0.0.0.0, ::, a loopback or a link-local address). It is recorded in the
setting server.addresses of tacctl.yaml, which 'host enroll --local' and
'tacctl install' write, and this server's own registry entry keeps a copy.

This release holds one address: 'add' sets it when none is set, 'replace'
changes it, and 'remove' of the only one is refused. A change snapshots first,
then moves the setting, the registry entry, the managed scope's prefixes and
this server's own PAM and accounts together (what 'host enroll --local
--server <ip>' does), and says what is left to do. Only the superuser runs it.

Examples:
  tacctl server addresses
  tacctl server addresses replace 192.0.2.10

`)
	return b.String()
}

// server dispatches: no sub-command, help, -h and --help are the usage
// (exit 0); anything else unknown is an error, then the usage (exit 1).
func (inv *invocation) server(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(serverHelp())
		return nil
	case "addresses":
		return inv.serverAddresses(rest)
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(serverHelp())
		return exit(1)
	}
}

// serverAddressesReadForm is the audit class's read forms of the verb: no
// word, 'list' and the help words change nothing.
func serverAddressesReadForm(rest []string) bool {
	return len(rest) == 0 || rest[0] == "list" || rest[0] == "-h" || rest[0] == "--help" || rest[0] == "help"
}

// serverAddressList reads the csv of an add, remove or replace: each element
// is a server address (conf.ServerAddressProblem), canonical, a repeated one
// counted once; more than one element is refused as a setting that holds
// them is (this release holds one).
func (inv *invocation) serverAddressList(csv string) ([]string, error) {
	var out []string
	for _, f := range strings.Split(csv, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if p := conf.ServerAddressProblem(f); p != "" {
			return nil, inv.usageErr("'" + f + "' " + p + ". Nothing was changed.")
		}
		if c := canonAddr(f); !contains(out, c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, inv.usageErr("No server address given. Nothing was changed.")
	}
	if len(out) > 1 {
		return nil, inv.usageErr(serverOnlyOneText + ". Nothing was changed.")
	}
	return out, nil
}

// serverAddresses is 'server addresses [list|add|remove|replace ...]'.
func (inv *invocation) serverAddresses(args []string) error {
	a := inv.app
	sub, csv := arg(args, 0), arg(args, 1)
	if len(args) > 2 {
		return inv.usageErr(serverUsage)
	}
	switch sub {
	case "", "list":
		if csv != "" {
			return inv.usageErr(serverUsage)
		}
		return inv.serverAddressesList()
	case "-h", "--help", "help":
		inv.write(serverHelp())
		return nil
	case "add", "remove", "replace":
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl server' for usage.")
	}
	if csv == "" {
		return inv.usageErr("Usage: tacctl server addresses " + sub + " <ip>[,<ip>...]")
	}
	if err := inv.confReadable(); err != nil {
		return err
	}
	want, err := inv.serverAddressList(csv)
	if err != nil {
		return err
	}
	addr := want[0]
	current := a.Conf().ServerAddress()
	switch sub {
	case "add":
		switch {
		case current == addr:
			a.Out.Info("No new address (already present: " + addr + ").")
			return nil
		case current != "":
			return inv.usageErr(serverAddUseText + ". Nothing was changed.")
		}
	case "remove":
		switch {
		case current != addr:
			a.Out.Warn("Nothing to remove (not present: " + addr + ").")
			return nil
		default:
			return inv.usageErr(serverNeedsText + ". Nothing was changed.")
		}
	case "replace":
		if current == addr {
			reg, err := inv.registry()
			if err != nil {
				return err
			}
			if e, ok := inv.localEntryOf(reg); !ok || canonAddr(e.Server) == addr {
				a.Out.Info("The server address is " + addr + " already. Nothing was changed.")
				return nil
			}
		}
	}
	return inv.serverAddressSet(sub, addr)
}

// serverAddressesList is 'server addresses list': the recorded address, and
// where it is read from when the setting does not hold it yet.
func (inv *invocation) serverAddressesList() error {
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	const title = "Server addresses"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	switch key, recorded := inv.app.Conf().ServerAddress(), inv.recordedServer(reg); {
	case key != "":
		inv.echo("  - " + key)
	case recorded != "":
		inv.echo("  - " + recorded + "  (this server's registry entry; the setting is written by the next 'host enroll --local')")
	default:
		inv.echo("  (none — 'tacctl host enroll --local' records the address of this machine, or: tacctl server addresses add <ip>)")
	}
	inv.echo("")
	return nil
}

// serverAddressSet makes addr the server address: with this server's login
// set up (a registry entry) the enrolment moves everything at once; without
// one only the setting changes, after a snapshot, and the login is set up by
// the enrolment, which reads it.
func (inv *invocation) serverAddressSet(op, addr string) error {
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	cur, have := inv.localEntryOf(reg)
	if have {
		return inv.serverAddressApply(op, enrollOpts{isLocal: true, name: cur.Name}, addr)
	}
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if err := inv.recordServerAddress(addr); err != nil {
		return err
	}
	inv.detail("server addresses", kvp("op", op), kvp("address", addr))
	inv.app.Out.InfoE("Server address set: " + addr + ". This machine's own login is not set up; it takes this address: " + ownLoginCommand)
	inv.app.Out.InfoE(serverFollowUps)
	return nil
}

// serverAddressMoves reports whether an explicit --server of 'host enroll
// --local' is another address than the recorded one (and a server address at
// all: a bad one is the enrolment's refusal), and the address in its canonical
// form. Nothing recorded is no move: the first address is the enrolment's.
func (inv *invocation) serverAddressMoves(given string) (string, bool) {
	if hosts.CheckServerAddress(given) != nil {
		return "", false
	}
	reg, err := inv.registry()
	if err != nil {
		return "", false
	}
	addr, recorded := canonAddr(given), inv.recordedServer(reg)
	return addr, recorded != "" && recorded != addr
}

// serverAddressApply is the change of the server address, the one code of
// 'server addresses add|replace' and of 'host enroll --local --server <ip>'
// with another address: a snapshot, then the enrolment of this server at addr
// (the setting, the registry entry, the managed scope's prefixes, the PAM and
// the accounts, each with the safeguards of the enrolment), then the
// follow-ups. o is the enrolment's command line (the name of the entry, the
// method it keeps).
func (inv *invocation) serverAddressApply(op string, o enrollOpts, addr string) error {
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	o.isLocal, o.server = true, addr
	if err := inv.hostEnrollRun(o); err != nil {
		return err
	}
	inv.detail("server addresses", kvp("op", op), kvp("address", addr))
	inv.app.Out.InfoE(serverFollowUps)
	return nil
}
