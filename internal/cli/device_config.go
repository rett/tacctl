package cli

// 'device config show <name>': a registered device's data, then the vendor
// walkthrough 'tacctl config <vendor> --scope <its scope> --name <name>'
// prints, built by the same in-process code (configDevice) with the device's
// own values in the SNMP step. Reading a device's configuration and pushing
// one come with the device-configuration releases (0.2.4, 0.2.5); this verb
// is the 'config' family's first word.

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

// deviceConfigUsage is the usage of 'device config'.
func deviceConfigUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device Configuration" + ui.NC + "\n\nUsage: tacctl device config <subcommand> [arguments]\n\nSubcommands:\n")
	for _, v := range deviceVerbs {
		if strings.Fields(v[0])[0] != "config" {
			continue
		}
		use := strings.TrimPrefix(v[0], "config ")
		b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 4) + v[1] + "\n")
		for _, o := range deviceOptions["config"] {
			fmt.Fprintf(&b, "      %-30s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
'show' prints what is registered for the device, then the walkthrough for its
vendor (cisco, juniper or wti) and the scope that covers its address, exactly
as 'tacctl config <vendor> --scope <scope> --name <name>' prints it, with the
device's location, description and name filling the SNMP step. A device whose
vendor is 'other', an enrolled Linux host and a device no scope's prefixes
cover have none.

Example:
  tacctl device config show core-sw1

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
		return inv.deviceConfigShow(args)
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
	inv.echo("")
}
