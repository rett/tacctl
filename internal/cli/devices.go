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

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devices"
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
		" [--protocol tacacs|radius]   (without --protocol: the scope's auth-method, else its only protocol, else tacacs)"
}

// configDevice is cmd_config_cisco, cmd_config_juniper and cmd_config_wti
// (with config_wti_radius) up to the rendering.
func (inv *invocation) configDevice(vendor string, args []string) error {
	a := inv.app
	usage := deviceUsage(vendor)
	var scope, protocol string
	legacy := false
	for i := 0; i < len(args); {
		switch w := args[i]; {
		case w == "--scope":
			if scope = arg(args, i+1); scope == "" {
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
	m, err := inv.model()
	if err != nil {
		return err
	}
	d := devices.Data{
		Model:       m,
		Conf:        a.Conf(),
		TemplateDir: a.Paths.Templates,
		ServerIP:    devices.ServerIP(inv.ctx, a.Runner),
	}
	if vendor != "wti" {
		d.ACL = devices.MgmtACL{CIDRs: inv.readMgmtACLCIDRs(scope), Name: inv.readMgmtACLName(vendor, scope)}
	}
	if protocol == devices.RADIUS {
		if d.Radius, err = inv.deviceRadius(vendor, scope); err != nil {
			return err
		}
	}
	return devices.Render(a.Out.Stdout, devices.Request{Vendor: vendor, Scope: scope, Legacy: legacy,
		Protocol: protocol, Source: source}, d)
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
