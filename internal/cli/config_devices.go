package cli

// 'config devices' (docs/plans/0.2.4-plan.md D68): how 'device config
// pull|diff' read the devices, the three device.config.* settings of
// tacctl.yaml. The verbs are the superuser's (no tier row names them), and a
// setting is checked by the schema, so an out-of-range value never reaches
// the file.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("devices", configDevicesFamilySpec, configDevicesCmd)
}

// configDevicesFamilySpec is the spec of 'config devices' as
// registerConfigVerb takes it.
var configDevicesFamilySpec = Spec{MaxArgs: 2, Args: []string{"show|max-concurrency|transport|timeout", ""}}

// configDevicesSpecs are the arguments of each verb.
var configDevicesSpecs = map[string]Spec{
	"show":            {MaxArgs: 0},
	"max-concurrency": {MaxArgs: 1, Args: []string{""}},
	"transport":       {MaxArgs: 1, Args: []string{"auto|netconf|ssh"}},
	"timeout":         {MaxArgs: 1, Args: []string{""}},
}

// configDevicesVerbs are the verbs ({Use, Short}), in usage order.
var configDevicesVerbs = [][2]string{
	{"show", "The three settings and where each stands"},
	{"max-concurrency [<n>]", "Show or set the most devices read at once, 1-64 (default 8)"},
	{"transport [auto|netconf|ssh]", "Show or set the default transport (auto: NETCONF where the device answers, else ssh)"},
	{"timeout [<seconds>]", "Show or set the time one device may take, connect included, 10-600 (default 90)"},
}

func configDevicesCmd(inv *invocation) *cobra.Command {
	c := verb("devices <subcommand>", "How 'device config pull' reads the devices (concurrency, transport, timeout)")
	c.RunE = inv.native(withPreflight, inv.configDevices)
	for _, v := range configDevicesVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.configDevices(append([]string{word}, args...))
		})))
	}
	return c
}

// configDevicesUsage is the usage of 'config devices'.
func configDevicesUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device reads" + ui.NC + "\n\nUsage: tacctl config devices [show|max-concurrency|transport|timeout] [value]\n\n")
	for _, v := range configDevicesVerbs {
		fmt.Fprintf(&b, "  %-32s  %s\n", v[0], v[1])
	}
	b.WriteString(`
These are the defaults of 'tacctl device config pull' and 'diff --pull' (in
tacctl.yaml as device.config.max_concurrency, .transport and .timeout).
--concurrency of one run can lower the concurrency, never raise it above the
setting; --transport and --timeout of one run replace the others for that
run. The setters are for administrators.

Examples:
  tacctl config devices
  tacctl config devices max-concurrency 16
  tacctl config devices transport ssh
  tacctl config devices timeout 120

`)
	return b.String()
}

// configDevices dispatches: no sub-command is 'show'; help, -h and --help
// are the usage (exit 0); an unknown one is an error, then the usage
// (exit 1).
func (inv *invocation) configDevices(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "show":
		return inv.configDevicesShow(rest)
	case "-h", "--help", "help":
		inv.write(configDevicesUsage())
		return nil
	case "max-concurrency":
		return inv.configDevicesSet(rest, "device.config.max_concurrency", "Devices read at once",
			"  Usage: tacctl config devices max-concurrency <1-64>", "The most devices read at once set to %v.")
	case "transport":
		return inv.configDevicesSet(rest, "device.config.transport", "Transport",
			"  Usage: tacctl config devices transport <auto|netconf|ssh>", "The default transport set to %v.")
	case "timeout":
		return inv.configDevicesSet(rest, "device.config.timeout", "Time per device",
			"  Usage: tacctl config devices timeout <10-600>", "The time one device may take set to %v s.")
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(configDevicesUsage())
		return exit(1)
	}
}

// configDevicesShow prints the three settings.
func (inv *invocation) configDevicesShow(rest []string) error {
	if len(rest) > 0 {
		return inv.usageErr("Unknown argument: '"+rest[0]+"'", "Usage: tacctl config devices [show|max-concurrency|transport|timeout] [value]")
	}
	s := inv.deviceConfigSettings()
	src := func(path string) string {
		if inv.app.Conf().HasOverride(path) {
			return "set"
		}
		return "default"
	}
	inv.echo("")
	inv.echo("  Device configuration reads ('tacctl device config pull|diff')")
	inv.echo("  max-concurrency: " + strconv.Itoa(s.maxConcurrency) + "   (" + src("device.config.max_concurrency") + "; 1-64: devices read at once)")
	inv.echo("  transport:       " + s.transport + "   (" + src("device.config.transport") + "; auto, netconf or ssh)")
	inv.echo("  timeout:         " + strconv.Itoa(int(s.timeout.Seconds())) + " s   (" + src("device.config.timeout") + "; 10-600, per device, connect included)")
	inv.echo("")
	return nil
}

// configDevicesSet shows or sets one key through the schema.
func (inv *invocation) configDevicesSet(rest []string, path, label, usage, done string) error {
	if len(rest) > 1 {
		return inv.usageErr("Unknown argument: '"+rest[1]+"'", strings.TrimSpace(usage))
	}
	def := map[string]string{"device.config.max_concurrency": "8", "device.config.transport": transportAuto, "device.config.timeout": "90"}[path]
	if len(rest) == 0 {
		inv.echo("")
		inv.echo("  " + label + ": " + inv.confGet(path, def))
		inv.echo("")
		inv.echo(usage)
		inv.echo("")
		return nil
	}
	if err := inv.app.Conf().Set(path, rest[0]); err != nil {
		return err
	}
	inv.app.Out.InfoE(strings.ReplaceAll(done, "%v", rest[0]))
	inv.echo("")
	return nil
}
