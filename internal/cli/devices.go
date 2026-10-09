package cli

// 'config cisco|juniper|wti' (lib/render_devices.sh cmd_config_cisco,
// cmd_config_juniper, cmd_config_wti at 0.1.16), native since WP3.1: the
// arguments, the scope and the protocol are settled here, in 0.1.16's
// order, so the same wrong command line gets the same first complaint;
// internal/devices builds and writes the config. The verbs replace
// config.go's declared words through registerConfigVerb; bin/tacctl.sh
// runs preflight before them.

import (
	"errors"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

// deviceVendors are the device verbs of 'config', with their Short.
var deviceVendors = []struct{ name, use, short string }{
	{"cisco", "cisco [--scope <name>] [--legacy] [--protocol tacacs|radius]",
		"Show working Cisco device configuration for a scope (--legacy = IOS 12.x syntax)"},
	{"juniper", "juniper [--scope <name>] [--protocol tacacs|radius]",
		"Show working Juniper device configuration for a scope"},
	{"wti", "wti [--scope <name>] [--protocol tacacs|radius]",
		"Show step-by-step WTI console-server (v8.x serial menu) setup for a scope"},
}

// deviceSpec is the arguments of a device verb, for completion.
func deviceSpec(vendor string) Spec {
	flags := []Flag{
		{Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--protocol"}, Value: true, Kind: "tacacs|radius"},
		{Names: []string{"--staging"}, Value: true},
		{Names: []string{"--name"}, Value: true},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--source"}, Value: true},
		{Names: []string{"--snmp-location"}, Value: true},
	}
	if vendor == "cisco" {
		flags = append(flags, Flag{Names: []string{"--legacy"}})
	}
	return Spec{Flags: flags}
}

func init() {
	for _, v := range deviceVendors {
		registerConfigVerb(v.name, deviceSpec(v.name), func(inv *invocation) *cobra.Command {
			return withRun(verb(v.use, v.short), inv.native(withPreflight, func(args []string) error {
				return inv.configDevice(v.name, args)
			}))
		})
	}
}

// deviceUsage is the usage line a device verb repeats on a bad argument.
func deviceUsage(vendor string) string {
	legacy := ""
	if vendor == "cisco" {
		legacy = " [--legacy]"
	}
	return "Usage: tacctl config " + vendor + " [--scope <name>]" + legacy +
		" [--protocol tacacs|radius] [--staging <bench-ip>] [--name <device>] [--server <address|name>] [--source <address>] [--snmp-location <text>]   (without --protocol: the scope's auth-method, else its only protocol, else tacacs)"
}

// configDevice is cmd_config_cisco, cmd_config_juniper and cmd_config_wti
// (with config_wti_radius) up to the rendering.
func (inv *invocation) configDevice(vendor string, args []string) error {
	a := inv.app
	usage := deviceUsage(vendor)
	var scope, protocol, stagingIP, stagingName, server, sourceFlag, snmpLocation string
	legacy := false
	for i := 0; i < len(args); {
		switch w := args[i]; {
		case w == "--scope":
			if scope = arg(args, i+1); scope == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--staging":
			if stagingIP = arg(args, i+1); stagingIP == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--name":
			if stagingName = arg(args, i+1); stagingName == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--server":
			if server = arg(args, i+1); server == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--source":
			if sourceFlag = arg(args, i+1); sourceFlag == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--snmp-location":
			if snmpLocation = arg(args, i+1); snmpLocation == "" {
				return inv.usageErr(usage)
			}
			i += 2
		case w == "--legacy" && vendor == "cisco":
			legacy = true
			i++
		case w == "--protocol":
			if protocol = arg(args, i+1); protocol == "" {
				return inv.usageErr(usage)
			}
			if msg := devices.ProtocolValid(protocol); msg != "" {
				return inv.usageErr(msg)
			}
			i += 2
		default:
			return inv.usageErr("Unknown argument: '"+w+"'", usage)
		}
	}
	if protocol == devices.RADIUS && legacy {
		return inv.usageErr("--legacy (IOS 12.x syntax) applies to TACACS+ only; the RADIUS configuration uses the structured 'radius server' block (IOS 15.2 / IOS-XE and later).")
	}
	authServer, authName, err := inv.deviceServerFlag(server)
	if err != nil {
		return err
	}
	if sourceFlag != "" {
		norm, err := devreg.NormalizeAddress(sourceFlag)
		if err != nil || strings.Contains(norm, ":") || strings.Contains(sourceFlag, "/") {
			return inv.usageErr("--source takes the IPv4 address tacctl reaches the devices from (a single address, no prefix length): '" + sourceFlag + "'")
		}
		sourceFlag = norm
	}
	if snmpLocation != "" {
		if err := devreg.ValidateLocation(snmpLocation); err != nil {
			return inv.usageErr(append(msgs(err), "(--snmp-location)")...)
		}
	}
	if stagingIP != "" {
		if scope == "" {
			return inv.usageErr("--staging provisions a device off-site for the scope it will be installed in; name it: --scope <scope>")
		}
		norm, err := devreg.NormalizeAddress(stagingIP)
		if err != nil || strings.Contains(norm, ":") || strings.Contains(stagingIP, "/") {
			return inv.usageErr("--staging takes the device's bench IPv4 address (a single address, no prefix length): '" + stagingIP + "'")
		}
		stagingIP = norm
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	if scope == "" {
		def, err := inv.defaultScope()
		if err != nil {
			return err
		}
		if def == "" {
			return inv.usageErr("No default scope set and no --scope provided.",
				"Run 'tacctl scope default <name>' or pass --scope <name>.")
		}
		scope = def
	} else if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	// The configuration carries the scope's secret: an engineer gets their
	// own scopes' only (D18).
	ownScopes := inv.callerScopes()
	if err := inv.ownScope(ownScopes, scope); err != nil {
		return err
	}
	// --staging --name ends the staging of a device of this scope: an
	// engineer names one of their own scopes' devices, not another's.
	// Fail closed: a registry that cannot be read is no proof the device is
	// the caller's.
	if stagingName != "" && ownScopes.restricted {
		_, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		// A host is not a device either: not found.
		if e, ok := res.NameTaken(stagingName); ok && (e.Source == devreg.SourceHost || !ownScopes.allows(e.Scope)) {
			return inv.usageErr("Device '" + stagingName + "' not found.")
		}
	}
	if ownScopes.restricted {
		inv.secretRead("scope", scope)
	}
	// No --protocol: the scope's auth-method, else its only protocol, else
	// TACACS+.
	choice, choiceSource := inv.scopeProtocolChoice(scope)
	protocol, source := devices.ResolveProtocol(protocol, choice, choiceSource)
	if protocol == devices.RADIUS && legacy {
		first := "Scope '" + scope + "' has auth-method radius (tacctl scope auth-method), and --legacy (IOS 12.x syntax) applies to TACACS+ only."
		if source == devices.SourceProtocols {
			first = "Scope '" + scope + "' is served over RADIUS only (tacctl scope protocols), and --legacy (IOS 12.x syntax) applies to TACACS+ only."
		}
		return inv.usageErr(first,
			"For the legacy TACACS+ configuration add --protocol tacacs: tacctl config cisco --scope "+scope+" --legacy --protocol tacacs")
	}
	// --name names a registered device whose SNMP location, description and
	// sysName the walkthrough uses (with --staging it also names the device
	// whose move ends the staging).
	var dev devices.SNMPInput
	if stagingName != "" {
		_, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		e, ok := res.NameTaken(stagingName)
		switch {
		case ok && e.Source == devreg.SourceDevice && ownScopes.allows(e.Scope) && (e.Scope == "" || e.Scope == scope):
			dev = deviceSNMPValues(e)
		case ok && e.Source == devreg.SourceDevice && ownScopes.allows(e.Scope) && stagingIP == "":
			return inv.usageErr("Device '" + stagingName + "' is in scope '" + e.Scope + "', not in '" + scope + "'. Nothing was printed.")
		case stagingIP == "":
			return inv.usageErr("Device '" + stagingName + "' not found. List them with: tacctl device list")
		}
	}
	if snmpLocation != "" {
		dev.Location = snmpLocation
	}
	if stagingIP != "" {
		// The device registered at the bench address, when no --name is
		// given, is the one whose move ends the staging.
		if stagingName == "" {
			if f, err := devreg.Load(a.Paths.DevicesFile); err == nil {
				if d := f.FindAddress(stagingIP); d != nil {
					stagingName = d.Name
				}
			}
		}
		// Everything the staging change prints (its own lines, the
		// snapshot's and the backends' render) goes to stderr: stdout is
		// the configuration.
		if err := inv.stdoutToStderr(func() error { return inv.stagingAdd(scope, stagingIP, "device", stagingName) }); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	d := devices.Data{
		Model:       m,
		Conf:        a.Conf(),
		TemplateDir: a.Paths.Templates,
		ServerIP:    devices.ServerIP(inv.ctx, a.Runner),
		Restricted:  ownScopes.restricted,
		AuthServer:  authServer, AuthName: authName, SourceIP: sourceFlag,
	}
	if d.SNMP, err = inv.walkthroughSNMP(scope, dev); err != nil {
		// A credentials file that cannot be read leaves the step out; the
		// rest of the walkthrough is still good.
		ui.Output{Stdout: a.Out.Stderr}.Warn("The SNMP step is left out: " + strings.Join(msgs(err), " "))
		d.SNMP = dev
		d.SNMP.Scope = scope
	}
	if ownScopes.restricted && d.SNMP.Version != "" {
		inv.secretRead("snmp", scope)
	}
	// The permit list is read for every vendor (WTI's IP Tables list, D42,
	// is built from it too); a WTI unit has no ACL name.
	d.ACL = devices.MgmtACL{CIDRs: inv.readMgmtACLCIDRs(scope)}
	if vendor != "wti" {
		d.ACL.Name = inv.readMgmtACLName(vendor, scope)
	}
	if protocol == devices.RADIUS {
		if d.Radius, err = inv.deviceRadius(vendor, scope); err != nil {
			return err
		}
	}
	return devices.Render(a.Out.Stdout, devices.Request{Vendor: vendor, Scope: scope, Legacy: legacy,
		Protocol: protocol, Source: source}, d)
}

// deviceSNMPValues are the SNMP values a registry device carries: its
// sysName (the DNS name when it has one, else its name), description and
// location.
func deviceSNMPValues(e devreg.Entry) devices.SNMPInput {
	sys := e.Hostname
	if sys == "" {
		sys = e.Name
	}
	return devices.SNMPInput{DeviceName: e.Name, SysName: sys, Description: e.Description, Location: e.Location}
}

// deviceServerFlag is --server (D43): the address the devices are told to
// authenticate against, and the host name it was resolved from ("" for an
// address). An IPv4 address is taken as it is; a name must resolve to one.
// Nothing is stored.
func (inv *invocation) deviceServerFlag(server string) (addr, name string, err error) {
	if server == "" {
		return "", "", nil
	}
	bad := "--server takes the IPv4 address the devices reach this server at, or a host name that resolves to one: '" + server + "'"
	if norm, nerr := devreg.NormalizeAddress(server); nerr == nil {
		if strings.Contains(norm, ":") || strings.Contains(server, "/") {
			return "", "", inv.usageErr(bad)
		}
		return norm, "", nil
	}
	if strings.ContainsAny(server, "/:") || devreg.ValidateHostname(server) != nil {
		return "", "", inv.usageErr(bad)
	}
	resolve := inv.app.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}
	addrs, rerr := resolve(inv.ctx, server)
	if rerr == nil {
		for _, a := range addrs {
			if n, nerr := devreg.NormalizeAddress(a); nerr == nil && !strings.Contains(n, ":") {
				return n, server, nil
			}
		}
	}
	return "", "", inv.usageErr("--server '" + server + "' does not resolve to an IPv4 address.")
}

// deviceRadius is radius_device_prepare: the RADIUS backend's part of a
// RADIUS device config, or its refusal (error lines, exit 1).
func (inv *invocation) deviceRadius(vendor, scope string) (*devices.Radius, error) {
	set := inv.app.Backends()
	ids, err := set.Enabled()
	if err != nil {
		return nil, inv.usageErr(err.Error())
	}
	enabled := false
	for _, id := range ids {
		enabled = enabled || id == backend.RADIUS
	}
	var b devices.RadiusBackend
	if enabled {
		rb, err := set.Get(backend.RADIUS)
		if err != nil {
			return nil, err
		}
		b = rb
	}
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	r, err := devices.Prepare(inv.ctx, vendor, scope, m, enabled, b)
	var refused *devices.RefusedError
	if errors.As(err, &refused) {
		return nil, inv.usageErr(refused.Lines...)
	}
	return r, err
}
