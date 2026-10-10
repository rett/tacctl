package cli

// 'device config': show, pull, diff, list and forget. 'show <name>' is a
// registered device's data, then the vendor walkthrough 'tacctl config
// <vendor> --scope <its scope> --name <name>' prints, built by the same
// in-process code (configDevice) with the device's own values in the SNMP
// step. 'pull' and 'diff' read the devices' configuration and compare the
// managed sections with what tacctl renders (device_config_pull.go,
// device_config_diff.go); 'list' and 'forget' are device_config_list.go.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// deviceConfigSpecs are the arguments of each 'device config' verb, for the
// parser and for completion (device.go's spec lookup).
var deviceConfigSpecs = func() map[string]Spec {
	selectors := []Flag{
		{Names: []string{"--all"}, Alone: true},
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--vendor"}, Value: true, Kind: "cisco|juniper|wti"},
		{Names: []string{"--stale"}},
	}
	read := []Flag{
		{Names: []string{"--transport"}, Value: true, Kind: "auto|netconf|ssh"},
		{Names: []string{"--concurrency"}, Value: true},
		{Names: []string{"--timeout"}, Value: true},
		{Names: []string{"--max-failures"}, Value: true},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--source"}, Value: true},
	}
	join := func(groups ...[]Flag) []Flag {
		var out []Flag
		for _, g := range groups {
			out = append(out, g...)
		}
		return out
	}
	return map[string]Spec{
		"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{
			{Names: []string{"--protocol"}, Value: true, Kind: "tacacs|radius"},
			{Names: []string{"--legacy"}},
			{Names: []string{"--server"}, Value: true},
			{Names: []string{"--source"}, Value: true}}},
		"pull": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, read, []Flag{{Names: []string{"--diff"}}, flagJSON})},
		"diff": {MaxArgs: -1, Args: []string{KindDevices + KindList},
			Flags: join(selectors, read, []Flag{{Names: []string{"--pull"}},
				{Names: []string{"--section"}, Value: true, Kind: strings.Join(devconf.SectionNames, "|") + KindList},
				flagJSON, {Names: []string{"--exit-code"}}})},
		"list": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stale"}}, {Names: []string{"--never"}}, {Names: []string{"--failed"}},
			{Names: []string{"--differs"}}, {Names: []string{"--transport"}, Value: true, Kind: "netconf|ssh|none"},
			{Names: []string{"--scope"}, Value: true, Kind: KindScopes}, {Names: []string{"--vendor"}, Value: true, Kind: "cisco|juniper|wti"},
			flagJSON}},
		"forget": {MaxArgs: -1, Args: []string{KindDevices + KindList}, Flags: []Flag{{Names: []string{"--all"}, Alone: true}}},
	}
}()

// deviceConfigVerbs are the 'device config' verbs in the order of device.go's
// rows.
var deviceConfigWords = []string{"show", "pull", "diff", "list", "forget"}

// deviceConfigUse is the usage of a 'device config' verb after
// 'tacctl device config ' (” for none).
func deviceConfigUse(sub string) string {
	for _, v := range deviceVerbs {
		if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "config" && f[1] == sub {
			return strings.TrimPrefix(v[0], "config ")
		}
	}
	return sub
}

// deviceConfigParse parses a 'device config' verb's arguments with its spec;
// a bad one is the error line and the verb's usage, exit 2 (argErr).
func (inv *invocation) deviceConfigParse(sub string, args []string) (Parsed, error) {
	p, err := Parse(deviceConfigSpecs[sub], args)
	if err == nil {
		return p, nil
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return p, inv.argErr(msg, "Usage: tacctl device config "+deviceConfigUse(sub))
}

// argErr is a wrong argument of the verbs that read the devices: the lines,
// and exit status 2, the status of a verb that checks its own arguments (a
// refusal of a name, a tier or a login is 1; so is a device that failed).
func (inv *invocation) argErr(msgs ...string) error {
	for _, m := range msgs {
		inv.app.Out.ErrorE(m)
	}
	return exit(batch.ExitUsage)
}

// deviceConfigNeeds is the lowest tier of each verb. The gate sees the two
// words 'device config' (its rows let an operator through for 'list' and an
// engineer for the rest); the verb holds each to its own tier, as 'scope
// snmp' does.
var deviceConfigNeeds = map[string]tier.Tier{
	"list": tier.Operator, "show": tier.Engineer, "pull": tier.Engineer, "diff": tier.Engineer, "forget": tier.Superuser,
}

// deviceConfigAllowed is nil when the caller's tier may run the verb; the
// refusal is the gate's, printed and logged.
func (inv *invocation) deviceConfigAllowed(sub string) error {
	need := deviceConfigNeeds[sub]
	g := inv.tierGate()
	t := g.Caller(inv.ctx)
	if t == tier.Unrestricted || t == tier.Superuser || (tier.Rank(t) >= 0 && tier.Rank(t) >= tier.Rank(need)) {
		return nil
	}
	user := inv.sudoUser()
	inv.app.Logger(inv.ctx, "auth.warning", "tier DENY user="+user+" tier="+string(t)+" cmd=device config "+sub)
	if t == tier.None {
		inv.app.Out.ErrorE("'" + g.SudoUser + "' has no active tacctl user, so tacctl access is denied.")
	} else {
		inv.app.Out.ErrorE("'tacctl device config " + sub + "' is not permitted for the " + string(t) + " tier.")
	}
	return tier.ErrDenied
}

// deviceConfigOptKey is the key of a verb's option lines in deviceOptions.
func deviceConfigOptKey(sub string) string { return "config " + sub }

// deviceConfigUsage is the usage of 'device config'.
func deviceConfigUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device Configuration" + ui.NC + "\n\nUsage: tacctl device config <subcommand> [arguments]\n\nSubcommands:\n")
	for _, w := range deviceConfigWords {
		use := deviceConfigUse(w)
		short := ""
		for _, v := range deviceVerbs {
			if f := strings.Fields(v[0]); len(f) > 1 && f[0] == "config" && f[1] == w {
				short = v[1]
			}
		}
		b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 4) + short + "\n")
		for _, o := range deviceOptions[deviceConfigOptKey(w)] {
			fmt.Fprintf(&b, "      %-34s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
'show' prints what is registered for the device, then the walkthrough for its
vendor (cisco, juniper or wti) and the scope that covers its address, exactly
as 'tacctl config <vendor> --scope <scope> --name <name>' prints it, with the
device's location, description and name filling the SNMP step. A device whose
vendor is 'other', an enrolled Linux host and a device no scope's prefixes
cover have none.

'pull' logs in to the devices as you (your username and your tacctl password,
asked for once, never stored or logged), reads each one's configuration over
NETCONF where it answers (Junos) or the ssh command line, and keeps the six
managed sections (aaa, roles, mgmt-acl, snmp, netconf, breakglass) with the
state of their comparison with what tacctl renders for that device. A secret
is compared by presence only and no secret value is kept or printed. A device
needs a pinned host key ('tacctl device hostkey <name> accept'); its scope
must be one of yours. At most device.config.max_concurrency devices are read
at once (--concurrency lowers it, never raises it). Ctrl-C stops starting new
devices; a second one cuts the running ones off. Exit status: 0 every device
read, 1 a device failed (or was refused), 2 wrong arguments, 130 interrupted.

'diff' compares the last pull with what tacctl renders now, section by
section: '-' is a statement tacctl renders that the device lacks, '+' one the
device has in a managed hierarchy that tacctl does not render, '!' a
reordering, '?' a secret the login could not see. --pull reads first.
--exit-code makes a difference exit 2.

'list' shows each device's state: ok (every managed section agrees), differs,
never (not pulled) or failed (the last pull failed), computed against today's
rendering, so a change in tacctl makes a device differ without a new pull.
--stale is never, failed and differs together. 'forget' deletes the records
(they are derived: a pull makes them again).

Examples:
  tacctl device config show core-sw1
  tacctl device config pull core-sw1
  tacctl device config pull --all --diff
  tacctl device config pull --scope lab --vendor juniper --concurrency 4
  tacctl device config diff core-sw1 --section aaa,snmp
  tacctl device config list --stale

`)
	return b.String()
}

// deviceConfig dispatches 'device config': no sub-command, help, -h and
// --help are the usage (exit 0); anything else unknown is an error, then the
// usage (exit 1).
func (inv *invocation) deviceConfig(args []string) error {
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(deviceConfigUsage())
		return nil
	case "show":
		if err := inv.deviceConfigAllowed("show"); err != nil {
			return err
		}
		return inv.deviceConfigShow(args)
	case "pull":
		return inv.deviceConfigPull(args[1:])
	case "diff":
		return inv.deviceConfigDiff(args[1:])
	case "list":
		return inv.deviceConfigList(args[1:])
	case "forget":
		return inv.deviceConfigForget(args[1:])
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(deviceConfigUsage())
		return exit(1)
	}
}

// deviceConfigShow is 'device config show <name> [--protocol ...]': args
// starts with "show".
func (inv *invocation) deviceConfigShow(args []string) error {
	p, err := inv.deviceParse("config", args)
	if err != nil {
		return err
	}
	if len(p.Args) < 2 {
		return inv.usageErr("Usage: tacctl device config show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>] [--source <address>]")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, p.Args[1])
	if err != nil {
		return err
	}
	switch {
	case e.Source == devreg.SourceHost:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; it has no device walkthrough. See: tacctl host show " + e.Name)
	case !slices.Contains(sortedVendors(), e.Vendor):
		return inv.usageErr("Device '"+e.Name+"' has vendor '"+e.Vendor+"', and only cisco, juniper and wti have a walkthrough.",
			"Set the vendor with: tacctl device vendor "+e.Name+" cisco|juniper|wti")
	case !e.Configured:
		return inv.usageErr("Device '"+e.Name+"' ("+dashAddrText(e.Address)+") is in no scope: no scope's prefixes cover its address.",
			"Add them with: tacctl scope prefixes <scope> add <cidr>")
	case p.Has("--legacy") && e.Vendor != "cisco":
		return inv.usageErr("--legacy (IOS 12.x syntax) applies to Cisco devices; '" + e.Name + "' is a " + e.Vendor + " device.")
	}
	cfg := []string{"--scope", e.Scope, "--name", e.Name}
	for _, f := range []string{"--protocol", "--server", "--source"} {
		if p.Has(f) {
			cfg = append(cfg, f, p.Value(f))
		}
	}
	if p.Has("--legacy") {
		cfg = append(cfg, "--legacy")
	}
	// The walkthrough is built first: a refusal prints no data block.
	var walk bytes.Buffer
	out := inv.app.Out
	inv.app.Out.Stdout = &walk
	err = inv.configDevice(e.Vendor, cfg)
	inv.app.Out = out
	if err != nil {
		return err
	}
	inv.printDeviceData(e)
	_, err = io.Copy(inv.app.Out.Stdout, &walk)
	return err
}

// printDeviceData is the data block of 'device config show': the device as
// registered, with the scope that covers it.
func (inv *invocation) printDeviceData(e devreg.Entry) {
	head := "Device " + e.Name
	inv.echo("")
	inv.echoE(ui.Bold + head + ui.NC)
	inv.echo(ui.Rule(head))
	row := func(k, v string) { inv.write(fmt.Sprintf("  %-13s %s\n", k+":", v)) }
	row("Name", e.Name)
	row("Address", dash(e.Address))
	row("Hostname", dash(e.Hostname))
	row("Vendor", e.Vendor)
	row("Scope", e.Scope+"  (via prefix "+e.Prefix+")")
	row("Description", dash(e.Description))
	row("Location", dash(e.Location))
	// What the SNMP step below is rendered with, and where each value comes
	// from (D72): the device's own over its scope's over the default.
	inv.deviceSNMPRows(e, func(k, v string) {
		if k == "" {
			inv.write(fmt.Sprintf("  %-13s %s\n", "", v))
			return
		}
		row(k, v)
	})
	inv.echo("")
}
